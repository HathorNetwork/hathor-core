import struct


def _test_bounds_struct_pack(fmt: str, lower_bound: int, upper_bound: int) -> None:
    struct.pack(fmt, lower_bound)
    try:
        struct.pack(fmt, lower_bound - 1)
    except struct.error:
        pass
    else:
        assert False
    struct.pack(fmt, upper_bound)
    try:
        struct.pack(fmt, upper_bound + 1)
    except struct.error:
        pass
    else:
        assert False


def test_int8_bounds() -> None:
    from hathor.nanocontracts.nc_types.sized_int_nc_type import _SizedIntNCType

    class Int8NCType(_SizedIntNCType):
        _signed = True
        _byte_size = 1

    lower_bound = Int8NCType._lower_bound_value()
    upper_bound = Int8NCType._upper_bound_value()

    assert lower_bound == -128
    assert upper_bound == 127

    _test_bounds_struct_pack('b', lower_bound, upper_bound)


def test_uint8_bounds() -> None:
    from hathor.nanocontracts.nc_types.sized_int_nc_type import _SizedIntNCType

    class Uint8NCType(_SizedIntNCType):
        _signed = False
        _byte_size = 1

    lower_bound = Uint8NCType._lower_bound_value()
    upper_bound = Uint8NCType._upper_bound_value()

    assert lower_bound == 0
    assert upper_bound == 255

    _test_bounds_struct_pack('B', lower_bound, upper_bound)


def test_int32_bounds() -> None:
    from hathor.nanocontracts.nc_types.sized_int_nc_type import Int32NCType

    lower_bound = Int32NCType._lower_bound_value()
    upper_bound = Int32NCType._upper_bound_value()

    assert lower_bound == -2147483648
    assert upper_bound == 2147483647

    _test_bounds_struct_pack('i', lower_bound, upper_bound)


def test_uint32_bounds() -> None:
    from hathor.nanocontracts.nc_types.sized_int_nc_type import Uint32NCType

    lower_bound = Uint32NCType._lower_bound_value()
    upper_bound = Uint32NCType._upper_bound_value()
    assert lower_bound == 0
    assert upper_bound == 4294967295
    _test_bounds_struct_pack('I', lower_bound, upper_bound)


def test_int64_bounds() -> None:
    from hathor.nanocontracts.nc_types.sized_int_nc_type import _SizedIntNCType

    class Int64NCType(_SizedIntNCType):
        _signed = True
        _byte_size = 8

    lower_bound = Int64NCType._lower_bound_value()
    upper_bound = Int64NCType._upper_bound_value()

    assert lower_bound == -9223372036854775808
    assert upper_bound == 9223372036854775807

    _test_bounds_struct_pack('q', lower_bound, upper_bound)


def test_uint64_bounds() -> None:
    from hathor.nanocontracts.nc_types.sized_int_nc_type import _SizedIntNCType

    class Uint64NCType(_SizedIntNCType):
        _signed = False
        _byte_size = 8

    lower_bound = Uint64NCType._lower_bound_value()
    upper_bound = Uint64NCType._upper_bound_value()

    assert lower_bound == 0
    assert upper_bound == 18446744073709551615

    _test_bounds_struct_pack('Q', lower_bound, upper_bound)
