"""Shared APDU builders and fixtures for the test suite."""
from app.audit import AuditFrame, audit_frames

C2S = "clientToServer"
S2C = "serverToClient"
ASDU = "01010300010000000000"  # opaque 10-octet ASDU placeholder

U_APDU = {
    ("startdt", "act"): "680407000000",
    ("startdt", "con"): "68040B000000",
    ("stopdt", "act"): "680413000000",
    ("stopdt", "con"): "680423000000",
    ("testfr", "act"): "680443000000",
    ("testfr", "con"): "680483000000",
}


def i_apdu(send: int, recv: int) -> str:
    ctrl = bytes([
        (send & 0x7F) << 1,
        (send >> 7) & 0xFF,
        (recv & 0x7F) << 1,
        (recv >> 7) & 0xFF,
    ])
    return "680E" + ctrl.hex() + ASDU


def s_apdu(recv: int) -> str:
    return "6804" + bytes([0x01, 0x00, (recv & 0x7F) << 1, (recv >> 7) & 0xFF]).hex()


# A complete, well-formed session: STARTDT, two client I frames confirmed by
# an S frame, one server I frame confirmed likewise, TESTFR and STOPDT pairs.
LEGAL_SESSION = [
    (C2S, U_APDU[("startdt", "act")]),
    (S2C, U_APDU[("startdt", "con")]),
    (C2S, i_apdu(0, 0)),
    (C2S, i_apdu(1, 0)),
    (S2C, s_apdu(2)),
    (S2C, i_apdu(0, 2)),
    (C2S, s_apdu(1)),
    (C2S, U_APDU[("testfr", "act")]),
    (S2C, U_APDU[("testfr", "con")]),
    (C2S, U_APDU[("stopdt", "act")]),
    (S2C, U_APDU[("stopdt", "con")]),
]


def audit(spec, max_unacked_window: int = 12):
    frames = [AuditFrame(direction=d, apdu_hex=a) for d, a in spec]
    return audit_frames(frames, max_unacked_window)


def request_frames(spec, start_us: int = 1_000_000, step_us: int = 1_000) -> list[dict]:
    return [
        {"capturedAtUs": start_us + i * step_us, "direction": d, "apduHex": a}
        for i, (d, a) in enumerate(spec)
    ]
