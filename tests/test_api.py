import pytest
from fastapi.testclient import TestClient

from app.main import app
from util import C2S, S2C, LEGAL_SESSION, U_APDU, i_apdu, request_frames

client = TestClient(app)
AUDIT_URL = "/api/iec104/sessions/audit"


def post(payload):
    return client.post(AUDIT_URL, json=payload)


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["version"]


def test_valid_session_returns_stats():
    resp = post({"maxUnackedWindow": 2, "frames": request_frames(LEGAL_SESSION)})
    assert resp.status_code == 200
    body = resp.json()
    assert body["verdict"] == "VALID"
    assert body["error"] is None
    assert body["stats"]["perDirection"] == {
        C2S: {"iFrames": 2, "unacked": 0},
        S2C: {"iFrames": 1, "unacked": 0},
    }
    assert body["stats"]["handshakes"] == {
        "startdt": {"act": 1, "con": 1},
        "stopdt": {"act": 1, "con": 1},
        "testfr": {"act": 1, "con": 1},
    }


def test_invalid_session_reports_first_violation_only():
    frames = request_frames([
        (C2S, i_apdu(0, 0)),        # I frame before STARTDT
        (C2S, "670407000000"),      # later defect must not leak into the verdict
    ])
    resp = post({"maxUnackedWindow": 12, "frames": frames})
    assert resp.status_code == 200
    body = resp.json()
    assert body["verdict"] == "INVALID"
    assert body["stats"] is None
    assert body["error"]["code"] == "I_NOT_STARTED"
    assert body["error"]["frameIndex"] == 0
    assert isinstance(body["error"]["message"], str) and body["error"]["message"]


def test_invalid_session_apdu_defect():
    frames = request_frames([(C2S, "680407000000FF")])
    resp = post({"maxUnackedWindow": 12, "frames": frames})
    assert resp.status_code == 200
    body = resp.json()
    assert body["verdict"] == "INVALID"
    assert body["error"]["code"] == "APDU_LENGTH"
    assert body["error"]["frameIndex"] == 0


def test_frames_must_be_non_decreasing():
    frames = request_frames([
        (C2S, U_APDU[("startdt", "act")]),
        (S2C, U_APDU[("startdt", "con")]),
    ])
    frames[1]["capturedAtUs"] = frames[0]["capturedAtUs"] - 1
    resp = post({"maxUnackedWindow": 12, "frames": frames})
    assert resp.status_code == 400
    body = resp.json()
    assert body["error"]["code"] == "FRAMES_NOT_ORDERED"
    assert body["error"]["frameIndex"] == 1


def test_equal_timestamps_are_accepted():
    frames = request_frames(LEGAL_SESSION, step_us=0)
    resp = post({"maxUnackedWindow": 2, "frames": frames})
    assert resp.status_code == 200
    assert resp.json()["verdict"] == "VALID"


@pytest.mark.parametrize("window", [0, -1, 16384, 100000])
def test_window_out_of_bounds(window):
    frames = request_frames([(C2S, U_APDU[("startdt", "act")])])
    resp = post({"maxUnackedWindow": window, "frames": frames})
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "INVALID_REQUEST"


def test_frame_count_bounds():
    assert post({"maxUnackedWindow": 12, "frames": []}).status_code == 400
    too_many = request_frames([(C2S, U_APDU[("testfr", "act")])] * 5001)
    assert post({"maxUnackedWindow": 12, "frames": too_many}).status_code == 400


def test_frame_count_upper_boundary_is_audited():
    frames = request_frames([(C2S, U_APDU[("testfr", "act")])] * 5000)
    resp = post({"maxUnackedWindow": 12, "frames": frames})
    assert resp.status_code == 200
    body = resp.json()
    assert body["verdict"] == "INVALID"
    assert body["error"]["code"] == "HANDSHAKE_ACT_REPEATED"
    assert body["error"]["frameIndex"] == 1


def test_unknown_direction_rejected():
    frames = request_frames([(C2S, U_APDU[("startdt", "act")])])
    frames[0]["direction"] = "eastbound"
    resp = post({"maxUnackedWindow": 12, "frames": frames})
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "INVALID_REQUEST"


def test_missing_and_extra_fields_rejected():
    resp = post({"maxUnackedWindow": 12})
    assert resp.status_code == 400
    frames = request_frames([(C2S, U_APDU[("startdt", "act")])])
    frames[0]["note"] = "tampered"
    resp = post({"maxUnackedWindow": 12, "frames": frames})
    assert resp.status_code == 400
