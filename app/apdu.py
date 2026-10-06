"""IEC 60870-5-104 APDU (APCI) parsing.

Only the APCI header is interpreted; the ASDU payload of I-format APDUs is
carried opaquely. A well-formed APDU has the layout::

    +--------+--------+---------------------------+===========+
    | 0x68   | length | control field (4 octets)  |   ASDU    |
    +--------+--------+---------------------------+===========+

``length`` counts every octet after the length field itself, so the APDU
must be exactly ``length + 2`` octets long -- neither truncated nor padded
with trailing bytes.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

START_BYTE = 0x68
CONTROL_FIELD_LEN = 4
SEQ_MODULO = 32768  # sequence numbers are 15-bit (mod 32768)

# U-format function bits in the first control octet (low two bits are 0b11).
U_FUNCTIONS = {
    0x04: ("startdt", "act"),
    0x08: ("startdt", "con"),
    0x10: ("stopdt", "act"),
    0x20: ("stopdt", "con"),
    0x40: ("testfr", "act"),
    0x80: ("testfr", "con"),
}


class Format(str, Enum):
    I = "I"
    S = "S"
    U = "U"


class ApduError(Exception):
    """Malformed APDU; ``code`` is a stable machine-readable identifier."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class Apdu:
    format: Format
    send_seq: int | None = None
    recv_seq: int | None = None
    u_function: tuple[str, str] | None = None  # (family, "act" | "con")


def parse_apdu(apdu_hex: str) -> Apdu:
    """Parse one hexadecimal APDU, raising :class:`ApduError` on any defect."""
    if (
        not apdu_hex
        or len(apdu_hex) % 2 != 0
        or any(ch not in "0123456789abcdefABCDEF" for ch in apdu_hex)
    ):
        raise ApduError("APDU_HEX_INVALID", "APDU is not an even-length hexadecimal string")
    raw = bytes.fromhex(apdu_hex)
    if len(raw) < 2:
        raise ApduError("APDU_LENGTH", "APDU is shorter than the start byte plus length field")
    if raw[0] != START_BYTE:
        raise ApduError("APDU_START_BYTE", f"start byte 0x{raw[0]:02X} is not 0x68")
    declared = raw[1]
    if declared < CONTROL_FIELD_LEN:
        raise ApduError(
            "APDU_LENGTH",
            f"length field {declared} cannot hold the 4-octet control field",
        )
    carried = len(raw) - 2
    if carried != declared:
        defect = "trailing bytes" if carried > declared else "truncated"
        raise ApduError(
            "APDU_LENGTH",
            f"length field declares {declared} octet(s) but {carried} present ({defect})",
        )

    b0, b1, b2, b3 = raw[2], raw[3], raw[4], raw[5]
    if b0 & 0x01 == 0:  # I format: numbered information transfer
        return Apdu(
            Format.I,
            send_seq=(b0 >> 1) | (b1 << 7),
            recv_seq=(b2 >> 1) | (b3 << 7),
        )
    if b0 & 0x03 == 0x01:  # S format: numbered supervisory
        if declared != CONTROL_FIELD_LEN:
            raise ApduError("APDU_CONTROL", "S-format APDU must have length 4")
        if b0 != 0x01 or b1 != 0x00:
            raise ApduError("APDU_CONTROL", "S-format reserved control bits must be zero")
        return Apdu(Format.S, recv_seq=(b2 >> 1) | (b3 << 7))
    # U format: unnumbered control (low two bits are 0b11)
    if declared != CONTROL_FIELD_LEN:
        raise ApduError("APDU_CONTROL", "U-format APDU must have length 4")
    if b1 != 0x00 or b2 != 0x00 or b3 != 0x00:
        raise ApduError("APDU_CONTROL", "U-format reserved control octets must be zero")
    function = U_FUNCTIONS.get(b0 & 0xFC)
    if function is None:
        raise ApduError("APDU_CONTROL", "U-format must set exactly one function bit")
    return Apdu(Format.U, u_function=function)
