import pytest


def _do_round_trip_test_with_size(n: int, encoded_size: int, signed: bool) -> None:
    from hathor.serialization import Deserializer, Serializer
    from hathor.serialization.encoding.leb128 import decode_leb128, encode_leb128
    se = Serializer.build_bytes_serializer()
    encode_leb128(se, n, signed=signed)
    encoded_n = bytes(se.finalize())
    assert len(encoded_n) == encoded_size
    de = Deserializer.build_bytes_deserializer(encoded_n)
    assert decode_leb128(de, signed=signed) == n


EXAMPLES_SIGNED_BY_SIZE = {
    1: [
        0,
        1,
        2,
        3,
        4,
        50,
        62,
        63,
        -1,
        -2,
        -3,
        -63,
        -64,
    ],
    2: [
        64,
        65,
        66,
        1000,
        3001,
        8190,
        8191,
        -65,
        -66,
        -67,
        -3000,
        -8191,
        -8192,
    ],
    3: [
        8192,
        8193,
        9000,
        100000,
        1048574,
        1048575,
        -8193,
        -8194,
        -100000,
        -1048575,
        -1048576,
    ],
}


def gen_signed_test_cases():
    test_cases = []
    # convert example to test cases
    for size, examples in EXAMPLES_SIGNED_BY_SIZE.items():
        for example in examples:
            test_cases.append((example, size))
    # generate additional test cases
    for size in range(4, 10):
        n_pos_lo = (1 << (7 * (size - 1) - 1))
        n_pos_hi = (1 << (7 * size - 1)) - 1
        n_neg_lo = -(1 << (7 * size - 1))
        n_neg_hi = -(1 << (7 * (size - 1) - 1)) - 1
        test_cases.append((n_pos_lo, size))
        test_cases.append((n_pos_hi, size))
        test_cases.append((n_neg_lo, size))
        test_cases.append((n_neg_hi, size))
    return test_cases


@pytest.mark.parametrize('n, encoded_size', gen_signed_test_cases())
def test_signed_round_trip_with_size(n, encoded_size):
    _do_round_trip_test_with_size(n, encoded_size, True)


EXAMPLES_UNSIGNED_BY_SIZE = {
    1: [
        0,
        1,
        2,
        3,
        4,
        50,
        62,
        63,
        64,
        126,
        127,
    ],
    2: [
        128,
        129,
        1000,
        3001,
        8190,
        8191,
        8192,
        16382,
        16383,
    ],
    3: [
        16384,
        100000,
        1048574,
        1048575,
        1048576,
        2097150,
        2097151,
    ],
}


def gen_unsigned_test_cases():
    test_cases = []
    # convert example to test cases
    for size, examples in EXAMPLES_UNSIGNED_BY_SIZE.items():
        for example in examples:
            test_cases.append((example, size))
    # generate additional test cases
    for size in range(4, 100):
        n_lo = 1 << (7 * (size - 1))
        n_hi = (1 << (7 * size)) - 1
        test_cases.append((n_lo, size))
        test_cases.append((n_hi, size))
    return test_cases


@pytest.mark.parametrize('n, encoded_size', gen_unsigned_test_cases())
def test_unsigned_round_trip_with_size(n, encoded_size):
    _do_round_trip_test_with_size(n, encoded_size, False)
