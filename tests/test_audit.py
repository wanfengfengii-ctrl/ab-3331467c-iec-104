import pytest

from app.audit import AuditError
from util import C2S, S2C, LEGAL_SESSION, U_APDU, audit, i_apdu, s_apdu


def expect_error(spec, code, index, window=12):
    with pytest.raises(AuditError) as excinfo:
        audit(spec, max_unacked_window=window)
    assert excinfo.value.code == code
    assert excinfo.value.frame_index == index
    assert excinfo.value.message


def test_legal_session_stats():
    stats = audit(LEGAL_SESSION, max_unacked_window=2)
    assert stats == {
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


def test_i_frame_before_startdt():
    expect_error([(C2S, i_apdu(0, 0))], "I_NOT_STARTED", 0)


def test_i_frame_after_stopdt():
    spec = [
        (C2S, U_APDU[("startdt", "act")]),
        (S2C, U_APDU[("startdt", "con")]),
        (C2S, U_APDU[("stopdt", "act")]),
        (S2C, U_APDU[("stopdt", "con")]),
        (C2S, i_apdu(0, 0)),
    ]
    expect_error(spec, "I_STOPPED", 4)


def test_send_sequence_must_be_contiguous():
    spec = [
        (C2S, U_APDU[("startdt", "act")]),
        (S2C, U_APDU[("startdt", "con")]),
        (C2S, i_apdu(0, 0)),
        (C2S, i_apdu(2, 0)),
    ]
    expect_error(spec, "SEQ_MISMATCH", 3)


def test_send_sequence_starts_at_zero():
    spec = [
        (C2S, U_APDU[("startdt", "act")]),
        (S2C, U_APDU[("startdt", "con")]),
        (C2S, i_apdu(7, 0)),
    ]
    expect_error(spec, "SEQ_MISMATCH", 2)


def test_ack_must_not_regress():
    spec = [
        (C2S, U_APDU[("startdt", "act")]),
        (S2C, U_APDU[("startdt", "con")]),
        (C2S, i_apdu(0, 0)),
        (C2S, i_apdu(1, 0)),
        (S2C, s_apdu(2)),
        (S2C, s_apdu(1)),
    ]
    expect_error(spec, "ACK_REGRESSION", 5)


def test_ack_must_not_pass_peer_send_count():
    spec = [
        (C2S, U_APDU[("startdt", "act")]),
        (S2C, U_APDU[("startdt", "con")]),
        (S2C, s_apdu(1)),
    ]
    expect_error(spec, "ACK_BEYOND_SENT", 2)


def test_unacked_window_limit():
    spec = [
        (C2S, U_APDU[("startdt", "act")]),
        (S2C, U_APDU[("startdt", "con")]),
        (C2S, i_apdu(0, 0)),
        (C2S, i_apdu(1, 0)),
    ]
    expect_error(spec, "WINDOW_EXCEEDED", 3, window=1)


def test_window_allows_exactly_k_unacked():
    spec = [
        (C2S, U_APDU[("startdt", "act")]),
        (S2C, U_APDU[("startdt", "con")]),
        (C2S, i_apdu(0, 0)),
        (C2S, i_apdu(1, 0)),
    ]
    stats = audit(spec, max_unacked_window=2)
    assert stats["perDirection"][C2S]["unacked"] == 2


def test_con_without_act():
    expect_error([(S2C, U_APDU[("startdt", "con")])], "HANDSHAKE_CON_WITHOUT_ACT", 0)


def test_act_repeated_before_con():
    spec = [
        (C2S, U_APDU[("testfr", "act")]),
        (S2C, U_APDU[("testfr", "act")]),
    ]
    expect_error(spec, "HANDSHAKE_ACT_REPEATED", 1)


def test_con_must_come_from_opposite_direction():
    spec = [
        (C2S, U_APDU[("startdt", "act")]),
        (C2S, U_APDU[("startdt", "con")]),
    ]
    expect_error(spec, "HANDSHAKE_SAME_DIRECTION", 1)


def test_unpaired_act_reported_at_earliest_act():
    spec = [
        (C2S, U_APDU[("startdt", "act")]),
        (S2C, U_APDU[("startdt", "con")]),
        (C2S, U_APDU[("testfr", "act")]),
        (C2S, U_APDU[("stopdt", "act")]),
    ]
    expect_error(spec, "HANDSHAKE_UNPAIRED_ACT", 2)


def test_first_violation_wins():
    spec = [
        (C2S, "670407000000"),   # bad start byte at frame 0
        (C2S, i_apdu(5, 0)),     # would also violate phase and sequence rules
    ]
    expect_error(spec, "APDU_START_BYTE", 0)


def test_restart_after_stopdt_is_legal():
    spec = [
        (C2S, U_APDU[("startdt", "act")]),
        (S2C, U_APDU[("startdt", "con")]),
        (C2S, U_APDU[("stopdt", "act")]),
        (S2C, U_APDU[("stopdt", "con")]),
        (C2S, U_APDU[("startdt", "act")]),
        (S2C, U_APDU[("startdt", "con")]),
        (C2S, i_apdu(0, 0)),
    ]
    stats = audit(spec)
    assert stats["handshakes"]["startdt"] == {"act": 2, "con": 2}
    assert stats["perDirection"][C2S] == {"iFrames": 1, "unacked": 1}


def test_final_unacked_reflects_missing_confirmations():
    spec = [
        (C2S, U_APDU[("startdt", "act")]),
        (S2C, U_APDU[("startdt", "con")]),
        (C2S, i_apdu(0, 0)),
        (C2S, i_apdu(1, 0)),
        (S2C, s_apdu(1)),
    ]
    stats = audit(spec)
    assert stats["perDirection"][C2S] == {"iFrames": 2, "unacked": 1}
    assert stats["perDirection"][S2C] == {"iFrames": 0, "unacked": 0}


def test_ack_carried_by_i_frame():
    spec = [
        (C2S, U_APDU[("startdt", "act")]),
        (S2C, U_APDU[("startdt", "con")]),
        (C2S, i_apdu(0, 0)),
        (S2C, i_apdu(0, 1)),
        (C2S, i_apdu(1, 1)),
        (S2C, s_apdu(2)),
    ]
    stats = audit(spec, max_unacked_window=2)
    assert stats["perDirection"][C2S]["unacked"] == 0
    assert stats["perDirection"][S2C]["unacked"] == 0
