#  Copyright 2025 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import struct
import zlib
from dataclasses import dataclass
from enum import Enum, unique
from types import CodeType
from typing import Callable, Final, Self, Sequence, TypeVar, assert_never

from hathor.conf.get_settings import get_global_settings
from hathor.conf.settings import HathorSettings
from hathor.nanocontracts.on_chain_blueprint import MAX_COMPRESSION_LEVEL, PYTHON_CODE_COMPAT_VERSION
from hathor.nanocontracts.utils import load_builtin_blueprint_for_ocb
from hathor.serialization import Serializer
from hathor.transaction.util import unpack, unpack_len
from hathor.utils import leb128
from tests.nanocontracts import test_blueprints  # skip-import-tests-custom-check

_BLUEPRINT_CO_ARGCOUNT: Final[int] = 0
_BLUEPRINT_CO_POSONLYARGCOUNT: Final[int] = 0
_BLUEPRINT_CO_KWONLYARGCOUNT: Final[int] = 0
_BLUEPRINT_CO_NLOCALS: Final[int] = 0
_BLUEPRINT_CO_FLAGS: Final[int] = 0
_BLUEPRINT_CO_VARNAMES: Final[tuple[str, ...]] = ()
_CO_FILENAME: Final[str] = '<blueprint>'
_BLUEPRINT_CO_NAME: Final[str] = '<module>'
_BLUEPRINT_CO_QUALNAME: Final[str] = '<module>'
_BLUEPRINT_CO_FIRSTLINENO: Final[int] = 1
_BLUEPRINT_CO_FREEVARS: Final[tuple[str, ...]] = ()
_BLUEPRINT_CO_CELLVARS: Final[tuple[str, ...]] = ()

T = TypeVar('T')

@dataclass(slots=True, frozen=True, kw_only=True)
class BasicCodeObject:
    co_stacksize: int
    co_code: bytes
    co_consts: tuple[object, ...]
    co_names: tuple[str, ...]
    co_linetable: bytes
    co_exceptiontable: bytes

    def write_bytes(self, serializer: Serializer) -> None:
        write_uint(serializer, self.co_stacksize)
        write_bytes(serializer, self.co_code)
        write_sequence(serializer, self.co_consts, write_const)
        write_sequence(serializer, self.co_names, write_string)
        write_bytes(serializer, self.co_linetable)
        write_bytes(serializer, self.co_exceptiontable)

    @classmethod
    def read_bytes(cls, buf: bytes) -> tuple[Self, bytes]:
        co_stacksize, buf = read_uint(buf)
        co_code, buf = read_bytes(buf)
        co_consts, buf = read_sequence(buf, read_const)
        co_names, buf = read_sequence(buf, read_string)
        co_linetable, buf = read_bytes(buf)
        co_exceptiontable, buf = read_bytes(buf)

        code_obj = cls(
            co_stacksize=co_stacksize,
            co_code=co_code,
            co_consts=tuple(co_consts),
            co_names=tuple(co_names),
            co_linetable=co_linetable,
            co_exceptiontable=co_exceptiontable,
        )
        return code_obj, buf


# TODO: Include Python version?
@dataclass(slots=True, frozen=True)
class BlueprintCodeObject:
    basic: BasicCodeObject

    @classmethod
    def from_source(cls, source: str) -> Self:
        code_obj = compile(
            source=source,
            filename='<blueprint>',
            mode='exec',
            flags=0,
            dont_inherit=True,
            optimize=0,
            _feature_version=PYTHON_CODE_COMPAT_VERSION[1],
        )
        return cls.from_code_obj(code_obj)

    @classmethod
    def from_code_obj(cls, code_obj: CodeType) -> Self:
        assert code_obj.co_argcount == _BLUEPRINT_CO_ARGCOUNT
        assert code_obj.co_posonlyargcount == _BLUEPRINT_CO_POSONLYARGCOUNT
        assert code_obj.co_kwonlyargcount == _BLUEPRINT_CO_KWONLYARGCOUNT
        assert code_obj.co_nlocals == _BLUEPRINT_CO_NLOCALS
        assert code_obj.co_flags == _BLUEPRINT_CO_FLAGS
        assert code_obj.co_varnames == _BLUEPRINT_CO_VARNAMES
        assert code_obj.co_filename == _CO_FILENAME
        assert code_obj.co_name == _BLUEPRINT_CO_NAME
        assert code_obj.co_qualname == _BLUEPRINT_CO_QUALNAME
        assert code_obj.co_firstlineno == _BLUEPRINT_CO_FIRSTLINENO
        assert code_obj.co_freevars == _BLUEPRINT_CO_FREEVARS
        assert code_obj.co_cellvars == _BLUEPRINT_CO_CELLVARS

        return cls(BasicCodeObject(
            co_stacksize=code_obj.co_stacksize,
            co_code=code_obj.co_code,
            co_consts=code_obj.co_consts,
            co_names=code_obj.co_names,
            co_linetable=code_obj.co_linetable,
            co_exceptiontable=code_obj.co_exceptiontable,
        ))

    def to_code_obj(self) -> CodeType:
        return CodeType(
            _BLUEPRINT_CO_ARGCOUNT,
            _BLUEPRINT_CO_POSONLYARGCOUNT,
            _BLUEPRINT_CO_KWONLYARGCOUNT,
            _BLUEPRINT_CO_NLOCALS,
            self.basic.co_stacksize,
            _BLUEPRINT_CO_FLAGS,
            self.basic.co_code,
            self.basic.co_consts,
            self.basic.co_names,
            _BLUEPRINT_CO_VARNAMES,
            _CO_FILENAME,
            _BLUEPRINT_CO_NAME,
            _BLUEPRINT_CO_QUALNAME,
            _BLUEPRINT_CO_FIRSTLINENO,
            self.basic.co_linetable,
            self.basic.co_exceptiontable,
            _BLUEPRINT_CO_FREEVARS,
            _BLUEPRINT_CO_CELLVARS,
        )

    @classmethod
    def from_bytes(cls, buf: bytes, settings: HathorSettings) -> Self:
        # TODO
        # if len(buf) > settings.NC_ON_CHAIN_BLUEPRINT_CODE_MAX_SIZE_COMPRESSED:
        #     raise ValueError

        basic, buf = BasicCodeObject.read_bytes(buf)
        assert len(buf) == 0
        return cls(basic)

    def to_bytes(self, settings: HathorSettings) -> bytes:
        # TODO
        # max_bytes = settings.NC_ON_CHAIN_BLUEPRINT_CODE_MAX_SIZE_COMPRESSED
        # serializer = Serializer.build_bytes_serializer().with_max_bytes(max_bytes)
        serializer = Serializer.build_bytes_serializer()
        self.basic.write_bytes(serializer)
        return bytes(serializer.finalize())


@dataclass(slots=True, frozen=True, kw_only=True)
class InnerCodeObject:
    basic: BasicCodeObject
    co_argcount: int
    co_posonlyargcount: int
    co_kwonlyargcount: int
    co_nlocals: int
    co_flags: int
    co_varnames: tuple[str, ...]
    co_name: str
    co_qualname: str
    co_firstlineno: int
    co_freevars: tuple[str, ...]
    co_cellvars: tuple[str, ...]

    @classmethod
    def from_code_obj(cls, code_obj: CodeType) -> Self:
        basic = BasicCodeObject(
            co_stacksize=code_obj.co_stacksize,
            co_code=code_obj.co_code,
            co_consts=code_obj.co_consts,
            co_names=code_obj.co_names,
            co_linetable=code_obj.co_linetable,
            co_exceptiontable=code_obj.co_exceptiontable,
        )

        return cls(
            basic=basic,
            co_argcount=code_obj.co_argcount,
            co_posonlyargcount=code_obj.co_posonlyargcount,
            co_kwonlyargcount=code_obj.co_kwonlyargcount,
            co_nlocals=code_obj.co_nlocals,
            co_flags=code_obj.co_flags,
            co_varnames=code_obj.co_varnames,
            co_name=code_obj.co_name,
            co_qualname=code_obj.co_qualname,
            co_firstlineno=code_obj.co_firstlineno,
            co_freevars=code_obj.co_freevars,
            co_cellvars=code_obj.co_cellvars,
        )

    def to_code_obj(self) -> CodeType:
        return CodeType(
            self.co_argcount,
            self.co_posonlyargcount,
            self.co_kwonlyargcount,
            self.co_nlocals,
            self.basic.co_stacksize,
            self.co_flags,
            self.basic.co_code,
            self.basic.co_consts,
            self.basic.co_names,
            self.co_varnames,
            _CO_FILENAME,
            self.co_name,
            self.co_qualname,
            self.co_firstlineno,
            self.basic.co_linetable,
            self.basic.co_exceptiontable,
            self.co_freevars,
            self.co_cellvars,
        )

    def write_bytes(self, serializer: Serializer) -> None:
        self.basic.write_bytes(serializer)
        write_uint(serializer, self.co_argcount)
        write_uint(serializer, self.co_posonlyargcount)
        write_uint(serializer, self.co_kwonlyargcount)
        write_uint(serializer, self.co_nlocals)
        write_uint(serializer, self.co_flags)
        write_sequence(serializer, self.co_varnames, write_string)
        write_string(serializer, self.co_name)
        write_string(serializer, self.co_qualname)
        write_uint(serializer, self.co_firstlineno)
        write_sequence(serializer, self.co_freevars, write_string)
        write_sequence(serializer, self.co_cellvars, write_string)

    @classmethod
    def read_bytes(cls, buf: bytes) -> tuple[Self, bytes]:
        basic, buf = BasicCodeObject.read_bytes(buf)
        co_argcount, buf = read_uint(buf)
        co_posonlyargcount, buf = read_uint(buf)
        co_kwonlyargcount, buf = read_uint(buf)
        co_nlocals, buf = read_uint(buf)
        co_flags, buf = read_uint(buf)
        co_varnames, buf = read_sequence(buf, read_string)
        co_name, buf = read_string(buf)
        co_qualname, buf = read_string(buf)
        co_firstlineno, buf = read_uint(buf)
        co_freevars, buf = read_sequence(buf, read_string)
        co_cellvars, buf = read_sequence(buf, read_string)

        inner = cls(
            basic=basic,
            co_argcount=co_argcount,
            co_posonlyargcount=co_posonlyargcount,
            co_kwonlyargcount=co_kwonlyargcount,
            co_nlocals=co_nlocals,
            co_flags=co_flags,
            co_varnames=tuple(co_varnames),
            co_name=co_name,
            co_qualname=co_qualname,
            co_firstlineno=co_firstlineno,
            co_freevars=tuple(co_freevars),
            co_cellvars=tuple(co_cellvars),
        )
        return inner, buf


def write_int(serializer: Serializer, n: int) -> None:
    serializer.write_bytes(leb128.encode_signed(n))


def read_int(buf: bytes) -> tuple[int, bytes]:
    return leb128.decode_signed(buf)


def write_uint(serializer: Serializer, n: int) -> None:
    serializer.write_bytes(leb128.encode_unsigned(n))


def read_uint(buf: bytes) -> tuple[int, bytes]:
    return leb128.decode_unsigned(buf)


def write_bytes(serializer: Serializer, data: bytes) -> None:
    write_uint(serializer, len(data))
    serializer.write_bytes(data)


def read_bytes(buf: bytes) -> tuple[bytes, bytes]:
    data_len, buf = read_uint(buf)
    return unpack_len(data_len, buf)


def write_sequence(serializer: Serializer, seq: Sequence[T], writer: Callable[[Serializer, T], None]) -> None:
    write_uint(serializer, len(seq))
    for item in seq:
        writer(serializer, item)


def read_sequence(buf: bytes, reader: Callable[[bytes], tuple[T, bytes]]) -> tuple[Sequence[T], bytes]:
    seq_len, buf = read_uint(buf)
    seq: list[T] = []
    for _ in range(seq_len):
        item, buf = reader(buf)
        seq.append(item)
    return seq, buf


def write_string(serializer: Serializer, s: str) -> None:
    write_bytes(serializer, s.encode('utf-8'))


def read_string(buf: bytes) -> tuple[str, bytes]:
    data, buf = read_bytes(buf)
    return data.decode('utf-8'), buf


@unique
class PythonConst(Enum):
    NONE     = b'\x00'
    STR      = b'\x01'
    BYTES    = b'\x02'
    INT      = b'\x03'
    FLOAT    = b'\x04'
    COMPLEX  = b'\x05'
    BOOL     = b'\x06'
    CODE     = b'\x07'
    TUPLE    = b'\x08'


def write_const(serializer: Serializer, const: object) -> None:
    match const:
        case None:
            serializer.write_bytes(PythonConst.NONE.value)

        case str():
            serializer.write_bytes(PythonConst.STR.value)
            write_string(serializer, const)

        case bytes():
            serializer.write_bytes(PythonConst.BYTES.value)
            write_bytes(serializer, const)

        case int():
            serializer.write_bytes(PythonConst.INT.value)
            write_int(serializer, const)

        case float():
            serializer.write_bytes(PythonConst.FLOAT.value)
            serializer.write_bytes(struct.pack('>d', const))

        case complex():
            raise NotImplementedError(f'complex is not supported')

        case bool():
            serializer.write_bytes(PythonConst.BOOL.value)
            serializer.write_bytes(b'\x01' if const else b'\x00')

        case CodeType():
            serializer.write_bytes(PythonConst.CODE.value)
            InnerCodeObject.from_code_obj(const).write_bytes(serializer)

        case tuple():
            serializer.write_bytes(PythonConst.TUPLE.value)
            write_sequence(serializer, const, write_const)

        case _:
            raise AssertionError(f'unexpected const type: {type(const)}')


def read_const(buf: bytes) -> tuple[object, bytes]:
    const_type, buf = unpack_len(1, buf)
    match PythonConst(const_type):
        case PythonConst.NONE:
            return None, buf

        case PythonConst.STR:
            return read_string(buf)

        case PythonConst.BYTES:
            return read_bytes(buf)

        case PythonConst.INT:
            return read_int(buf)

        case PythonConst.FLOAT:
            return unpack('>d', buf)

        case PythonConst.COMPLEX:
            raise NotImplementedError(f'complex is not supported')

        case PythonConst.BOOL:
            return unpack_len(1, buf)

        case PythonConst.CODE:
            inner, buf = InnerCodeObject.read_bytes(buf)
            return inner.to_code_obj(), buf

        case PythonConst.TUPLE:
            seq, buf = read_sequence(buf, read_const)
            return tuple(seq), buf

        case _:
            assert_never(const_type)


def print_code_obj(code_obj: CodeType) -> None:
    print(f'co_argcount = {code_obj.co_argcount}')
    print(f'co_posonlyargcount = {code_obj.co_posonlyargcount}')
    print(f'co_kwonlyargcount = {code_obj.co_kwonlyargcount}')
    print(f'co_nlocals = {code_obj.co_nlocals}')
    print(f'co_stacksize = {code_obj.co_stacksize}')
    print(f'co_flags = {code_obj.co_flags}')
    print(f'co_code = 0x{code_obj.co_code.hex()}')
    print(f'co_consts = {code_obj.co_consts}')
    print(f'co_names = {code_obj.co_names}')
    print(f'co_varnames = {code_obj.co_varnames}')
    print(f'co_filename = {code_obj.co_filename}')
    print(f'co_name = {code_obj.co_name}')
    print(f'co_qualname = {code_obj.co_qualname}')
    print(f'co_firstlineno = {code_obj.co_firstlineno}')
    print(f'co_linetable = 0x{code_obj.co_linetable.hex()}')
    print(f'co_exceptiontable = 0x{code_obj.co_exceptiontable.hex()}')
    print(f'co_freevars = {code_obj.co_freevars}')
    print(f'co_cellvars = {code_obj.co_cellvars}')
    print()


settings = get_global_settings()
bet = load_builtin_blueprint_for_ocb('bet.py', 'Bet', test_blueprints)
swap = load_builtin_blueprint_for_ocb('swap_demo.py', 'SwapDemo', test_blueprints)
dozer = load_builtin_blueprint_for_ocb('dozer.py', 'DozerPoolManager', test_blueprints)
simple = '''
y = 1

def baz(x):
    print(x + y)
    return 1 + 1

a = baz(234234)
'''

code = BlueprintCodeObject.from_source(dozer)
# print_code_obj(code.to_code_obj())
round_trip = BlueprintCodeObject.from_bytes(code.to_bytes(settings), settings)
env: dict = {}
exec(round_trip.to_code_obj(), env)
print('SUCCESS!')

sources = dict(
    betb=bet,
    swap=swap,
    dozer=dozer,
    simple=simple,
)
cols = ('name', 'raw', 'compressed', 'bp_code', 'compressed_bp')

print('\t\t'.join(cols))
print('-' * 70)
for name, source in sources.items():
    raw_code = source.encode('utf-8')
    compressed_code = zlib.compress(raw_code, level=MAX_COMPRESSION_LEVEL)

    blueprint_code = BlueprintCodeObject.from_source(source)
    bp_bytes = blueprint_code.to_bytes(settings)
    compressed_bp = zlib.compress(bp_bytes, level=MAX_COMPRESSION_LEVEL)

    row = (raw_code, compressed_code, bp_bytes, compressed_bp)
    print(name + '\t\t' + '\t\t'.join([str(len(x)) for x in row]))
