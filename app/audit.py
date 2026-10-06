"""Stateful IEC 60870-5-104 session auditor.

Frames are evaluated strictly in capture order and the audit aborts on the
first violation, so the reported frame index is always the earliest frame
affected by a defect -- no later verdicts are produced.

Audited invariants:

* both directions start their send sequence at 0 and number I frames
  contiguously (a capture holds at most 5000 frames, well below the 32768
  sequence modulus, so sequence numbers never wrap inside one audit);
* a receive (acknowledgement) sequence never regresses, never acknowledges
  more I frames than the peer has sent, and never leaves more than
  ``max_unacked_window`` of the peer's I frames unconfirmed;
* every STARTDT / STOPDT / TESTFR ``act`` is paired with exactly one ``con``
  from the opposite direction before the capture ends;
* I frames appear only while data transfer is active, i.e. after a STARTDT
  handshake completed and before a STOPDT handshake completed.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from .apdu import ApduError, Format, parse_apdu

DIRECTIONS = ("clientToServer", "serverToClient")
HANDSHAKE_FAMILIES = ("startdt", "stopdt", "testfr")


@dataclass(frozen=True)
class AuditFrame:
    direction: str
    apdu_hex: str


class AuditError(Exception):
    """First session violation; ``code`` is stable and machine-readable."""

    def __init__(self, code: str, frame_index: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.frame_index = frame_index
        self.message = message


@dataclass
class _DirectionState:
    sent: int = 0           # I frames transmitted by this direction
    acked_by_peer: int = 0  # highest recv sequence the peer has returned
    last_ack_sent: int = 0  # highest recv sequence this direction has announced


def _peer(direction: str) -> str:
    return DIRECTIONS[1] if direction == DIRECTIONS[0] else DIRECTIONS[0]


def audit_frames(frames: Sequence[AuditFrame], max_unacked_window: int) -> dict:
    """Audit one captured session and return its statistics.

    Raises :class:`AuditError` at the earliest offending frame.
    """
    state = {d: _DirectionState() for d in DIRECTIONS}
    handshakes = {fam: {"act": 0, "con": 0} for fam in HANDSHAKE_FAMILIES}
    pending: dict[str, tuple[str, int]] = {}  # family -> (act direction, frame index)
    started = False  # a STARTDT handshake has completed and no STOPDT since
    stopped = False  # a STOPDT handshake has completed at least once

    def check_ack(index: int, direction: str, recv_seq: int) -> None:
        st = state[direction]
        peer_st = state[_peer(direction)]
        if recv_seq < st.last_ack_sent:
            raise AuditError(
                "ACK_REGRESSION",
                index,
                f"{direction} acknowledges {recv_seq} after already acknowledging "
                f"{st.last_ack_sent}",
            )
        if recv_seq > peer_st.sent:
            raise AuditError(
                "ACK_BEYOND_SENT",
                index,
                f"{direction} acknowledges {recv_seq} but the peer has sent only "
                f"{peer_st.sent} I frame(s)",
            )
        st.last_ack_sent = recv_seq
        peer_st.acked_by_peer = recv_seq

    for index, frame in enumerate(frames):
        try:
            apdu = parse_apdu(frame.apdu_hex)
        except ApduError as exc:
            raise AuditError(exc.code, index, exc.message) from exc
        direction = frame.direction

        if apdu.format is Format.I:
            if not started:
                code = "I_STOPPED" if stopped else "I_NOT_STARTED"
                phase = "stopped" if stopped else "not yet started"
                raise AuditError(code, index, f"I frame while data transfer is {phase}")
            st = state[direction]
            if apdu.send_seq != st.sent:
                raise AuditError(
                    "SEQ_MISMATCH",
                    index,
                    f"{direction} sends sequence {apdu.send_seq}, expected {st.sent}",
                )
            check_ack(index, direction, apdu.recv_seq)
            st.sent += 1
            unacked = st.sent - st.acked_by_peer
            if unacked > max_unacked_window:
                raise AuditError(
                    "WINDOW_EXCEEDED",
                    index,
                    f"{direction} leaves {unacked} unacknowledged I frame(s), "
                    f"window allows at most {max_unacked_window}",
                )
        elif apdu.format is Format.S:
            check_ack(index, direction, apdu.recv_seq)
        else:  # U format: connection handshake
            family, kind = apdu.u_function
            if kind == "act":
                if family in pending:
                    _, first_idx = pending[family]
                    raise AuditError(
                        "HANDSHAKE_ACT_REPEATED",
                        index,
                        f"{family} act repeated before the act at frame {first_idx} "
                        f"was confirmed",
                    )
                pending[family] = (direction, index)
            else:
                if family not in pending:
                    raise AuditError(
                        "HANDSHAKE_CON_WITHOUT_ACT",
                        index,
                        f"{family} con without a preceding act",
                    )
                act_dir, act_idx = pending.pop(family)
                if act_dir == direction:
                    raise AuditError(
                        "HANDSHAKE_SAME_DIRECTION",
                        index,
                        f"{family} con must answer an act from the opposite direction "
                        f"(act at frame {act_idx})",
                    )
                if family == "startdt":
                    started, stopped = True, False
                elif family == "stopdt":
                    started, stopped = False, True
            handshakes[family][kind] += 1

    if pending:
        family, (act_dir, act_idx) = min(pending.items(), key=lambda item: item[1][1])
        raise AuditError(
            "HANDSHAKE_UNPAIRED_ACT",
            act_idx,
            f"{family} act from {act_dir} was never confirmed",
        )

    return {
        "perDirection": {
            d: {
                "iFrames": state[d].sent,
                "unacked": state[d].sent - state[d].acked_by_peer,
            }
            for d in DIRECTIONS
        },
        "handshakes": handshakes,
    }
