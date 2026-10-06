import pytest

from app.apdu import ApduError, Format, parse_apdu


def test_parse_i_frame():
    apdu = parse_apdu("680E06000A00" + "01010300010000000000")
    assert apdu.format is Format.I
    assert apdu.send_seq == 3
    assert apdu.recv_seq == 5


def test_parse_i_frame_high_sequence_numbers():
    apdu = parse_apdu("680E" + "FEFF" + "FCFF" + "01010300010000000000")
    assert apdu.send_seq == 32767
    assert apdu.recv_seq == 32766


def test_parse_s_frame():
    apdu = parse_apdu("680401000800")
    assert apdu.format is Format.S
    assert apdu.recv_seq == 4


@pytest.mark.parametrize(
    "hex_apdu,family,kind",
    [
        ("680407000000", "startdt", "act"),
        ("68040B000000", "startdt", "con"),
        ("680413000000", "stopdt", "act"),
        ("680423000000", "stopdt", "con"),
        ("680443000000", "testfr", "act"),
        ("680483000000", "testfr", "con"),
    ],
)
def test_parse_u_functions(hex_apdu, family, kind):
    apdu = parse_apdu(hex_apdu)
    assert apdu.format is Format.U
    assert apdu.u_function == (family, kind)


@pytest.mark.parametrize(
    "hex_apdu,code",
    [
        ("", "APDU_HEX_INVALID"),
        ("680", "APDU_HEX_INVALID"),          # odd number of hex digits
        ("ZZ0407000000", "APDU_HEX_INVALID"),
        ("68 04 07 00 00 00", "APDU_HEX_INVALID"),  # embedded whitespace
        ("68", "APDU_LENGTH"),                # missing length field
        ("670407000000", "APDU_START_BYTE"),
        ("6803070000", "APDU_LENGTH"),        # length below control field
        ("680507000000", "APDU_LENGTH"),      # truncated
        ("680407000000FF", "APDU_LENGTH"),    # trailing byte
        ("68040F000000", "APDU_CONTROL"),     # two U function bits
        ("680403000000", "APDU_CONTROL"),     # no U function bit
        ("680407010000", "APDU_CONTROL"),     # U reserved octet set
        ("68050100000000", "APDU_CONTROL"),   # S format with length 5
        ("680401010000", "APDU_CONTROL"),     # S reserved octet set
        ("680481000000", "APDU_CONTROL"),     # S format with reserved bits set
    ],
)
def test_rejected_apdus(hex_apdu, code):
    with pytest.raises(ApduError) as excinfo:
        parse_apdu(hex_apdu)
    assert excinfo.value.code == code
