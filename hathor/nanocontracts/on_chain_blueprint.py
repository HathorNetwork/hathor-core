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

from __future__ import annotations

import ast
import zlib
from dataclasses import InitVar, dataclass, field
from enum import IntEnum, unique
from typing import TYPE_CHECKING, Any, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from structlog import get_logger
from typing_extensions import Self, override

from hathor.conf.get_settings import get_global_settings
from hathor.crypto.util import get_address_b58_from_public_key_bytes, get_public_key_bytes_compressed
from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.exception import OCBOutOfFuelDuringLoading, OCBOutOfMemoryDuringLoading
from hathor.nanocontracts.method import Method
from hathor.nanocontracts.types import BLUEPRINT_EXPORT_NAME, BlueprintId, blueprint_id_from_bytes
from hathor.transaction import Transaction, TxInput, TxOutput, TxVersion
from hathor.transaction.util import VerboseCallback, int_to_bytes, unpack, unpack_len

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings
    from hathor.nanocontracts.storage import NCContractStorage  # noqa: F401
    from hathor.transaction.storage import TransactionStorage  # noqa: F401

logger = get_logger()

# used to allow new versions of the serialization format in the future
ON_CHAIN_BLUEPRINT_VERSION: int = 1

# source compatibility with Python 3.11
PYTHON_CODE_COMPAT_VERSION = (3, 11)

# max compression level, used as default
MAX_COMPRESSION_LEVEL = 9


@unique
class CodeKind(IntEnum):
    """ Represents what type of code and format is being used, to allow new code/compression types in the future.
    """

    PYTHON_ZLIB = 1

    def __bytes__(self) -> bytes:
        return int_to_bytes(number=self.value, size=1)


def _compress_code(content: str, compress_level: int) -> bytes:
    # XXX: zlib is gzip compatible and compresses slightly better
    return zlib.compress(content.encode('utf-8'), level=compress_level)


def _decompress_code(data: bytes, max_length: int) -> str:
    dcobj = zlib.decompressobj()
    content = dcobj.decompress(data, max_length=max_length)
    if dcobj.unconsumed_tail:
        raise ValueError('Decompressed code is too long.')
    return content.decode('utf-8')


@dataclass(frozen=True)
class Code:
    """ Store the code object in memory, along with helper methods.
    """

    # determines how the content will be interpreted
    kind: CodeKind

    # the encoded content, usually encoded implies compressed
    data: bytes

    # pre-decompressed content, for faster access
    text: str = field(init=False)

    # only needed for initialization, to decompress the original data
    settings: InitVar[HathorSettings]

    def __post_init__(self, settings: HathorSettings) -> None:
        # used to initialize self.text with
        match self.kind:
            case CodeKind.PYTHON_ZLIB:
                text = _decompress_code(self.data, settings.NC_ON_CHAIN_BLUEPRINT_CODE_MAX_SIZE_UNCOMPRESSED)
                # set self.text using object.__setattr__ to bypass frozen protection
                object.__setattr__(self, 'text', text)
            case _:
                raise ValueError('Invalid code kind value')

    def __bytes__(self) -> bytes:
        # Code serialization format: [kind:variable bytes][null byte][data:variable bytes]
        if self.kind is not CodeKind.PYTHON_ZLIB:
            raise ValueError('Invalid code kind value')
        buf = bytearray()
        buf.extend(bytes(self.kind))
        buf.extend(self.data)
        return bytes(buf)

    @classmethod
    def from_bytes(cls, data: bytes, settings: HathorSettings) -> Self:
        """ Parses a Code instance from a byte sequence, the length of the data is encoded outside of this class.

        NOTE: This will not validate whether the encoded has a valid compression format. A Validator must be used to
        check that.
        """
        data = bytearray(data)
        kind = CodeKind(data[0])
        if kind is not CodeKind.PYTHON_ZLIB:
            raise ValueError('Code kind not supported')
        compressed_code = data[1:]
        return cls(kind, compressed_code, settings)

    @classmethod
    def from_python_code(
        cls,
        text_code: str,
        settings: HathorSettings,
        *,
        compress_level: int = MAX_COMPRESSION_LEVEL,
    ) -> Self:
        data = _compress_code(text_code, compress_level)
        return cls(CodeKind.PYTHON_ZLIB, data, settings)

    def to_json(self) -> dict[str, Any]:
        """ Simple json view."""
        import base64
        return {
            'kind': self.kind.value,
            'content': base64.b64encode(self.data).decode('ascii'),
        }

    def to_json_extended(self) -> dict[str, Any]:
        """ Extended json view, includes content in text form."""
        return {
            **self.to_json(),
            'content_text': self.text,
        }


class OnChainBlueprint(Transaction):
    """On-chain blueprint vertex to be placed on the DAG of transactions."""

    MIN_NUM_INPUTS = 0

    def __init__(
        self,
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
        storage: Optional['TransactionStorage'] = None,
    ) -> None:
        super().__init__(nonce=nonce, timestamp=timestamp, version=version, weight=weight, inputs=inputs,
                         outputs=outputs or [], tokens=tokens, parents=parents or [], hash=hash, storage=storage)

        self._settings = get_global_settings()
        if not self._settings.ENABLE_NANO_CONTRACTS:
            raise RuntimeError('NanoContracts are disabled')

        # Pubkey and signature of the transaction owner / caller.
        self.nc_pubkey: bytes = b''
        self.nc_signature: bytes = b''

        self.code: Code = code if code is not None else Code(CodeKind.PYTHON_ZLIB, b'', self._settings)
        self._ast_cache: Optional[ast.Module] = None
        self._blueprint_loaded_env: Optional[tuple[type[Blueprint], dict[str, object]]] = None

    def blueprint_id(self) -> BlueprintId:
        """The blueprint's contract-id is it's own tx-id, this helper method just converts to the right type."""
        return blueprint_id_from_bytes(self.hash)

    def _load_blueprint_code_exec(self) -> tuple[object, dict[str, object]]:
        """XXX: DO NOT CALL THIS METHOD UNLESS YOU REALLY KNOW WHAT IT DOES."""
        from hathor.nanocontracts.metered_exec import MeteredExecutor, OutOfFuelError, OutOfMemoryError
        fuel = self._settings.NC_INITIAL_FUEL_TO_LOAD_BLUEPRINT_MODULE
        memory_limit = self._settings.NC_MEMORY_LIMIT_TO_LOAD_BLUEPRINT_MODULE
        metered_executor = MeteredExecutor(fuel=fuel, memory_limit=memory_limit)
        try:
            env = metered_executor.exec(self.code.text)
        except OutOfFuelError as e:
            self.log.error('loading blueprint module failed, fuel limit exceeded')
            raise OCBOutOfFuelDuringLoading from e
        except OutOfMemoryError as e:
            self.log.error('loading blueprint module failed, memory limit exceeded')
            raise OCBOutOfMemoryDuringLoading from e
        blueprint_class = env[BLUEPRINT_EXPORT_NAME]
        return blueprint_class, env

    def _load_blueprint_code(self) -> tuple[type[Blueprint], dict[str, object]]:
        """This method loads the on-chain code (if not loaded) and returns the blueprint class and env."""
        if self._blueprint_loaded_env is None:
            blueprint_class, env = self._load_blueprint_code_exec()
            assert isinstance(blueprint_class, type)
            assert issubclass(blueprint_class, Blueprint)
            self._blueprint_loaded_env = blueprint_class, env
        return self._blueprint_loaded_env

    def get_blueprint_object_bypass(self) -> object:
        """Loads the code and returns the object exported with @export"""
        blueprint_class, _ = self._load_blueprint_code_exec()
        return blueprint_class

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
        code = Code.from_bytes(serialized_code, settings)
        return code, buf

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

    def get_method(self, method_name: str) -> Method:
        # XXX: possibly do this by analyzing the source AST instead of using the loaded code
        blueprint_class = self.get_blueprint_class()
        return Method.from_callable(getattr(blueprint_class, method_name))

    def sign(self, private_key: ec.EllipticCurvePrivateKey) -> None:
        """Sign this blueprint with the provided private key."""
        pubkey = private_key.public_key()
        self.nc_pubkey = get_public_key_bytes_compressed(pubkey)
        data = self.get_sighash_all_data()
        self.nc_signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))

    def get_related_addresses(self) -> set[str]:
        """Besides the common tx related addresses, we must also add the nc_pubkey."""
        ret = super().get_related_addresses()
        ret.add(get_address_b58_from_public_key_bytes(self.nc_pubkey))
        return ret
