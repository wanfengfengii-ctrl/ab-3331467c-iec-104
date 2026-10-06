"""One-shot verification service.

Runs three steps against a cleanly started compose stack and reports via the
process exit code (0 = everything passed, 1 = at least one check failed):

1. code tests -- the pytest suite shipped in the image;
2. image build coherence -- the ``api`` container must answer ``/health``
   with the same application version as this image, proving both containers
   run the image built from this source tree;
3. smoke audits -- one legal session and a set of illegal sessions are sent
   to the live HTTP API and their verdicts asserted.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

API_BASE_URL = os.environ.get("API_BASE_URL", "http://127.0.0.1:8080").rstrip("/")
AUDIT_URL = API_BASE_URL + "/api/iec104/sessions/audit"

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

FAILURES: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    print(f"[{'PASS' if condition else 'FAIL'}] {name}", flush=True)
    if not condition:
        if detail:
            print(f"       {detail}", flush=True)
        FAILURES.append(name)


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


def session_frames(spec, start_us: int = 1_000_000) -> list[dict]:
    return [
        {"capturedAtUs": start_us + i * 1000, "direction": d, "apduHex": a}
        for i, (d, a) in enumerate(spec)
    ]


def post_audit(payload: dict) -> tuple[int, dict]:
    req = urllib.request.Request(
        AUDIT_URL,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())
    except urllib.error.URLError as exc:
        return 0, {"error": {"code": "UNREACHABLE", "message": str(exc)}}


def run_code_tests() -> None:
    print("== step 1/3: code tests ==", flush=True)
    import pytest

    check("code tests (pytest)", pytest.main(["-q", "tests"]) == 0)


def run_build_check() -> None:
    print("== step 2/3: image build coherence ==", flush=True)
    from app import APP_VERSION

    try:
        with urllib.request.urlopen(API_BASE_URL + "/health", timeout=10) as resp:
            health = json.loads(resp.read())
    except Exception as exc:  # noqa: BLE001 - any failure means the stack is broken
        check("api /health reachable", False, repr(exc))
        return
    check("api /health reachable", health.get("status") == "ok", json.dumps(health))
    check(
        "api image matches source version",
        health.get("version") == APP_VERSION,
        f"api={health.get('version')} source={APP_VERSION}",
    )


def run_smoke_audits() -> None:
    print("== step 3/3: smoke audits ==", flush=True)

    legal = session_frames([
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
    ])
    status, body = post_audit({"maxUnackedWindow": 2, "frames": legal})
    check(
        "legal session verdict",
        status == 200 and body.get("verdict") == "VALID",
        f"status={status} body={json.dumps(body)}",
    )
    expected_stats = {
        "perDirection": {
            C2S: {"iFrames": 2, "unacked": 0},
            S2C: {"iFrames": 1, "unacked": 0},
        },
        "handshakes": {
            "startdt": {"act": 1, "con": 1},
            "stopdt": {"act": 1, "con": 1},
            "testfr": {"act": 1, "con": 1},
        },
    }
    check(
        "legal session stats",
        body.get("stats") == expected_stats,
        f"stats={json.dumps(body.get('stats'))}",
    )

    illegal_cases = [
        (
            "I frame before STARTDT",
            12,
            [(C2S, i_apdu(0, 0))],
            "I_NOT_STARTED",
            0,
        ),
        (
            "bad start byte",
            12,
            [(C2S, "670407000000")],
            "APDU_START_BYTE",
            0,
        ),
        (
            "trailing bytes",
            12,
            [(C2S, "68040700000000")],
            "APDU_LENGTH",
            0,
        ),
        (
            "unacked window exceeded",
            1,
            [
                (C2S, U_APDU[("startdt", "act")]),
                (S2C, U_APDU[("startdt", "con")]),
                (C2S, i_apdu(0, 0)),
                (C2S, i_apdu(1, 0)),
            ],
            "WINDOW_EXCEEDED",
            3,
        ),
        (
            "send sequence skip",
            12,
            [
                (C2S, U_APDU[("startdt", "act")]),
                (S2C, U_APDU[("startdt", "con")]),
                (C2S, i_apdu(0, 0)),
                (C2S, i_apdu(2, 0)),
            ],
            "SEQ_MISMATCH",
            3,
        ),
        (
            "unpaired TESTFR act",
            12,
            [
                (C2S, U_APDU[("startdt", "act")]),
                (S2C, U_APDU[("startdt", "con")]),
                (C2S, U_APDU[("testfr", "act")]),
            ],
            "HANDSHAKE_UNPAIRED_ACT",
            2,
        ),
        (
            "con from same direction",
            12,
            [
                (C2S, U_APDU[("startdt", "act")]),
                (C2S, U_APDU[("startdt", "con")]),
            ],
            "HANDSHAKE_SAME_DIRECTION",
            1,
        ),
    ]
    for name, window, spec, code, index in illegal_cases:
        status, body = post_audit({"maxUnackedWindow": window, "frames": session_frames(spec)})
        error = body.get("error") or {}
        ok = (
            status == 200
            and body.get("verdict") == "INVALID"
            and body.get("stats") is None
            and error.get("code") == code
            and error.get("frameIndex") == index
            and bool(error.get("message"))
        )
        check(f"illegal session: {name}", ok, f"status={status} body={json.dumps(body)}")

    status, body = post_audit({"maxUnackedWindow": 12, "frames": []})
    check(
        "empty capture rejected with 400",
        status == 400 and (body.get("error") or {}).get("code") == "INVALID_REQUEST",
        f"status={status} body={json.dumps(body)}",
    )


def main() -> int:
    run_code_tests()
    run_build_check()
    run_smoke_audits()
    if FAILURES:
        print(f"verify: FAIL ({len(FAILURES)} check(s) failed)", flush=True)
        return 1
    print("verify: PASS", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
