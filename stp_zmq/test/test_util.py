import pytest

from stp_zmq.util import convert_z85_to_base58

Z85_KEY_1 = "?efW/K<z?A4&N##L}%-ucvN&$8f#Lq6PjpeE/7Qy"
BASE58_KEY = "FuN98eH2eZybECWkofW6A9BKJxxnTatBCopfUiNxo6ZB"

Z85_KEY_BAD = "?efW/K<z?A4&N##L}%-ucvN$8f#Lq6PjpeE/7Qy"


def test_convert_z85_to_base58():
    assert convert_z85_to_base58(Z85_KEY_1) == BASE58_KEY

    with pytest.raises(ValueError):
        convert_z85_to_base58(Z85_KEY_BAD)

    with pytest.raises(ValueError):
        convert_z85_to_base58(None)