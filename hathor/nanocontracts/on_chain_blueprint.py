# Copyright 2024 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import zlib
from enum import Enum
from typing import TYPE_CHECKING, Any, NamedTuple, Optional

from structlog import get_logger
from typing_extensions import Self, override

from hathor.conf.get_settings import get_global_settings
from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.method_parser import NCMethodParser
from hathor.nanocontracts.types import BlueprintId, VertexId
from hathor.transaction import Transaction, TxInput, TxOutput, TxVersion
from hathor.transaction.util import VerboseCallback, int_to_bytes, unpack, unpack_len

if TYPE_CHECKING:
    from hathor.nanocontracts.storage import NCStorage  # noqa: F401
    from hathor.transaction.storage import TransactionStorage  # noqa: F401

logger = get_logger()

# used to allow new versions of the serialization format in the future
ON_CHAIN_BLUEPRINT_VERSION: int = 1

# this is the name we expect the source code to expose for the Blueprint class
BLUEPRINT_CLASS_NAME: str = '__blueprint__'

# list of allowed builtins during execution of an on-chain blueprint code
EXEC_ALLOWED_BUILTINS: set[str] = {
    'False',
    'None',
    'True',
    '__build_class__',
    '__import__',
    '__name__',
    'abs',
    'all',
    'any',
    'ascii',
    'bin',
    'bool',
    'bytearray',
    'bytes',
    'classmethod',
    'complex',
    'dict',
    'divmod',
    'enumerate',
    'filter',
    'float',
    'format',
    'hex',
    'int',
    'iter',
    'len',
    'list',
    'max',
    'min',
    'next',
    'pow',
    'property',
    'range',
    'round',
    'set',
    'slice',
    'staticmethod',
    'str',
    'sum',
    'super',
    'tuple',
    'type',
    'zip',
    'sorted',
    'oct',
    'ord',
    'frozenset',
    'chr',
    'map',
    'hash',
    'callable',
    # These are the ones that were omitted:
    # 'ArithmeticError',
    # 'AssertionError',
    # 'AttributeError',
    # 'BaseException',
    # 'BaseExceptionGroup',
    # 'BlockingIOError',
    # 'BrokenPipeError',
    # 'BufferError',
    # 'BytesWarning',
    # 'ChildProcessError',
    # 'ConnectionAbortedError',
    # 'ConnectionError',
    # 'ConnectionRefusedError',
    # 'ConnectionResetError',
    # 'DeprecationWarning',
    # 'EOFError',
    # 'Ellipsis',
    # 'EncodingWarning',
    # 'EnvironmentError',
    # 'Exception',
    # 'ExceptionGroup',
    # 'FileExistsError',
    # 'FileNotFoundError',
    # 'FloatingPointError',
    # 'FutureWarning',
    # 'GeneratorExit',
    # 'IOError',
    # 'ImportError',
    # 'ImportWarning',
    # 'IndentationError',
    # 'IndexError',
    # 'InterruptedError',
    # 'IsADirectoryError',
    # 'KeyError',
    # 'KeyboardInterrupt',
    # 'LookupError',
    # 'MemoryError',
    # 'ModuleNotFoundError',
    # 'NameError',
    # 'NotADirectoryError',
    # 'NotImplemented',
    # 'NotImplementedError',
    # 'OSError',
    # 'OverflowError',
    # 'PendingDeprecationWarning',
    # 'PermissionError',
    # 'ProcessLookupError',
    # 'RecursionError',
    # 'ReferenceError',
    # 'ResourceWarning',
    # 'RuntimeError',
    # 'RuntimeWarning',
    # 'StopAsyncIteration',
    # 'StopIteration',
    # 'SyntaxError',
    # 'SyntaxWarning',
    # 'SystemError',
    # 'SystemExit',
    # 'TabError',
    # 'TimeoutError',
    # 'TypeError',
    # 'UnboundLocalError',
    # 'UnicodeDecodeError',
    # 'UnicodeEncodeError',
    # 'UnicodeError',
    # 'UnicodeTranslateError',
    # 'UnicodeWarning',
    # 'UserWarning',
    # 'ValueError',
    # 'Warning',
    # 'ZeroDivisionError',
    # '__debug__',
    # '__doc__',
    # '__loader__',
    # '__package__',
    # '__spec__',
    # 'aiter',
    # 'anext',
    # 'breakpoint',
    # 'compile',
    # 'copyright',
    # 'credits',
    # 'delattr',
    # 'dir',
    # 'eval',
    # 'exec',
    # 'exit',
    # 'getattr',
    # 'globals',
    # 'hasattr',
    # 'help',
    # 'id',
    # 'input',
    # 'isinstance',
    # 'issubclass',
    # 'license',
    # 'locals',
    # 'memoryview',
    # 'object',
    # 'open',
    # 'print',
    # 'quit',
    # 'repr',
    # 'reversed',
    # 'setattr',
    # 'vars',
}


class CodeKind(Enum):
    """ Represents what type of code and format is being used, to allow new code/compression types in the future.
    """

    PYTHON_GZIP = 'python+gzip'

    def __bytes__(self) -> bytes:
        return self.value.encode()


class Code(NamedTuple):
    """ Store the code object in memory, along with helper methods.
    """

    # determines how the content will be interpreted
    kind: CodeKind

    # the actual content, usually the uncompressed code in utf-8 bytes
    content: bytes

    def text(self) -> str:
        """ Returns the content in text form (str).
        """
        match self.kind:
            case CodeKind.PYTHON_GZIP:
                return self.content.decode()
            case _:
                raise ValueError('Invalid code kind value')

    def __bytes__(self) -> bytes:
        # Code serialization format: [kind:variable bytes][null byte][content:variable bytes]
        if self.kind is not CodeKind.PYTHON_GZIP:
            raise ValueError('Invalid code kind value')
        # XXX: zlib is gzip compatible and compresses slightly better
        zcode = zlib.compress(self.content)
        buf = bytearray()
        buf.extend(bytes(self.kind))
        buf.append(0)
        buf.extend(zcode)
        return bytes(buf)

    @classmethod
    def from_bytes(cls, data: bytes, max_length: int) -> Self:
        """ Parses a Code instance from a byte sequence, the length of the data is encoded outside of this class."""
        data = bytearray(data)
        cut_at = data.index(0)
        kind = CodeKind(data[0:cut_at].decode())
        dcobj = zlib.decompressobj()
        content = dcobj.decompress(data[cut_at + 1:], max_length=max_length)
        if not dcobj.eof:
            raise ValueError('Decompressed code is too long.')
        return cls(kind, content)

    def to_json(self) -> dict[str, Any]:
        """ Simple json view."""
        import base64
        return {
            'kind': self.kind.value,
            'content': base64.b64encode(self.content).decode('ascii'),
        }

    def to_json_extended(self) -> dict[str, Any]:
        """ Extended json view, includes content in text form."""
        return {
            **self.to_json(),
            'content_text': self.text(),
        }


class OnChainBlueprint(Transaction):
    """On-chain blueprint vertex to be placed on the DAG of transactions."""

    MIN_NUM_INPUTS = 0

    def __init__(self,
                 nonce: int = 0,
                 timestamp: Optional[int] = None,
                 version: TxVersion = TxVersion.ON_CHAIN_BLUEPRINT,
                 weight: float = 0,
                 inputs: Optional[list[TxInput]] = None,
                 outputs: Optional[list[TxOutput]] = None,
                 parents: Optional[list[bytes]] = None,
                 tokens: Optional[list[bytes]] = None,
                 code: Optional[Code] = None,
                 hash: Optional[bytes] = None,
                 storage: Optional['TransactionStorage'] = None) -> None:
        super().__init__(nonce=nonce, timestamp=timestamp, version=version, weight=weight, inputs=inputs,
                         outputs=outputs or [], tokens=tokens, parents=parents or [], hash=hash, storage=storage)

        self._settings = get_global_settings()
        if not self._settings.ENABLE_ON_CHAIN_BLUEPRINTS:
            assert self._settings.ENABLE_NANO_CONTRACTS, 'OnChainBlueprints require NanoContracts to be enabled'
            raise RuntimeError('OnChainBlueprints are disabled')

        # Pubkey and signature of the transaction owner / caller.
        self.nc_pubkey: bytes = b''
        self.nc_signature: bytes = b''

        self.code: Code = code if code is not None else Code(CodeKind.PYTHON_GZIP, b'')
        self._blueprint_loaded_env: Optional[tuple[type[Blueprint], dict[str, object]]] = None

    def blueprint_id(self) -> BlueprintId:
        """The blueprint's contract-id is it's own tx-id, this helper method just converts to the right type."""
        return BlueprintId(VertexId(self.hash))

    def _load_blueprint_code_exec(self) -> tuple[type[Blueprint], dict[str, object]]:
        """XXX: DO NOT CALL THIS METHOD UNLESS YOU REALLY KNOW WHAT IT DOES."""
        import builtins
        env: dict[str, object] = {
            '__builtins__': {attr: getattr(builtins, attr) for attr in EXEC_ALLOWED_BUILTINS},
        }
        # XXX: SECURITY: "exec" MUST NOT BE USED IN ANY CODE THAT ACCEPTS DATA FROM THE INTERNET
        exec(self.code.text(), env)
        blueprint_class = env[BLUEPRINT_CLASS_NAME]
        assert isinstance(blueprint_class, type)
        assert issubclass(blueprint_class, Blueprint)
        del env['__builtins__']
        return blueprint_class, env

    def _load_blueprint_code(self) -> tuple[type[Blueprint], dict[str, object]]:
        """This method loads the on-chain code (if not loaded) and returns the blueprint class and env."""
        if self._blueprint_loaded_env is None:
            self._blueprint_loaded_env = self._load_blueprint_code_exec()
        return self._blueprint_loaded_env

    def get_blueprint_class(self) -> type[Blueprint]:
        """Returns the blueprint class, loads and executes the code as needed."""
        blueprint_class, _ = self._load_blueprint_code()
        return blueprint_class

    def serialize_code(self) -> bytes:
        """Serialization of self.code, to be used for the serialization of this transaction type."""
        buf = bytearray()
        buf.extend(int_to_bytes(ON_CHAIN_BLUEPRINT_VERSION, 1))
        serialized_code = bytes(self.code)
        buf.extend(int_to_bytes(len(serialized_code), 4))
        buf.extend(serialized_code)
        return bytes(buf)

    @classmethod
    def deserialize_code(_cls, buf: bytes, *, verbose: VerboseCallback = None) -> tuple[Code, bytes]:
        """Parses the self.code field, returns the parse result and the remaining bytes."""
        settings = get_global_settings()

        (ocb_version,), buf = unpack('!B', buf)
        if verbose:
            verbose('ocb_version', ocb_version)
        if ocb_version != ON_CHAIN_BLUEPRINT_VERSION:
            raise ValueError(f'unknown on-chain blueprint version: {ocb_version}')

        (serialized_code_len,), buf = unpack('!L', buf)
        if verbose:
            verbose('serialized_code_len', serialized_code_len)
        max_serialized_code_len = settings.NC_ON_CHAIN_BLUEPRINT_CODE_MAX_SIZE_COMPRESSED
        if serialized_code_len > max_serialized_code_len:
            raise ValueError(f'compressed code data is too large: {serialized_code_len} > {max_serialized_code_len}')
        serialized_code, buf = unpack_len(serialized_code_len, buf)
        if verbose:
            verbose('serialized_code', serialized_code)
        code = Code.from_bytes(
            serialized_code,
            max_length=settings.NC_ON_CHAIN_BLUEPRINT_CODE_MAX_SIZE_UNCOMPRESSED,
        )
        return code, buf

    def _serialize_ocb(self, *, skip_signature: bool = True) -> bytes:
        buf = bytearray()
        buf += self.serialize_code()
        buf += int_to_bytes(len(self.nc_pubkey), 1)
        buf += self.nc_pubkey
        if not skip_signature:
            buf += int_to_bytes(len(self.nc_signature), 1)
            buf += self.nc_signature
        else:
            buf += int_to_bytes(0, 1)
        return bytes(buf)

    @override
    def get_funds_struct(self) -> bytes:
        struct_bytes = super().get_funds_struct()
        struct_bytes += self._serialize_ocb()
        return struct_bytes

    @override
    def get_sighash_all(self, *, skip_cache: bool = False) -> bytes:
        if not skip_cache and self._sighash_cache:
            return self._sighash_cache
        struct_bytes = super().get_sighash_all(skip_cache=True)
        struct_bytes += self._serialize_ocb(skip_signature=True)
        self._sighash_cache = struct_bytes
        return struct_bytes

    @override
    def get_funds_fields_from_struct(self, buf: bytes, *, verbose: VerboseCallback = None) -> bytes:
        buf = super().get_funds_fields_from_struct(buf, verbose=verbose)

        code, buf = OnChainBlueprint.deserialize_code(buf, verbose=verbose)
        self.code = code

        (nc_pubkey_len,), buf = unpack('!B', buf)
        if verbose:
            verbose('nc_pubkey_len', nc_pubkey_len)
        self.nc_pubkey, buf = unpack_len(nc_pubkey_len, buf)
        if verbose:
            verbose('nc_pubkey', self.nc_pubkey)
        (nc_signature_len,), buf = unpack('!B', buf)
        if verbose:
            verbose('nc_signature_len', nc_signature_len)
        self.nc_signature, buf = unpack_len(nc_signature_len, buf)
        if verbose:
            verbose('nc_signature', self.nc_signature)

        return buf

    @override
    def to_json(self, decode_script: bool = False, include_metadata: bool = False) -> dict[str, Any]:
        return {
            **super().to_json(decode_script=decode_script, include_metadata=include_metadata),
            'on_chain_blueprint_code': self.code.to_json(),
            'nc_pubkey': self.nc_pubkey.hex(),
        }

    @override
    def to_json_extended(self) -> dict[str, Any]:
        return {
            **super().to_json_extended(),
            'on_chain_blueprint_code': self.code.to_json_extended(),
            'nc_pubkey': self.nc_pubkey.hex(),
            'nc_signature': self.nc_signature.hex(),
        }

    @override
    def get_minimum_number_of_inputs(self) -> int:
        return 0

    def get_method_parser(self, method_name: str) -> NCMethodParser:
        # XXX: possibly do this by analyzing the source AST instead of using the loaded code
        blueprint_class = self.get_blueprint_class()
        return NCMethodParser(getattr(blueprint_class, method_name))
