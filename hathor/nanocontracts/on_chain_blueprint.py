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
import sys
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
from hathor.nanocontracts.exception import OCBOutOfFuelDuringLoading
from hathor.nanocontracts.method import Method
from hathor.nanocontracts.sandbox import DISABLED_CONFIG, SandboxCounts, SandboxError
from hathor.nanocontracts.types import BLUEPRINT_EXPORT_NAME, BlueprintId, blueprint_id_from_bytes
from hathor.transaction import Transaction, TxInput, TxOutput, TxVersion
from hathor.transaction.util import VerboseCallback, int_to_bytes, unpack, unpack_len

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings
    from hathor.nanocontracts.metered_exec import MeteredExecutor
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


@dataclass(frozen=True, slots=True)
class BlueprintCache:
    """Cached result of loading an on-chain blueprint.

    Attributes:
        blueprint_class: The loaded Blueprint subclass.
        env: The execution environment from loading.
        loading_costs: Sandbox counter deltas from loading.
                       Default (zero counts) when sandbox was not active during loading.
    """

    blueprint_class: type[Blueprint]
    env: dict[str, object]
    loading_costs: SandboxCounts = field(default_factory=SandboxCounts)


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
        self._blueprint_cache: BlueprintCache | None = None

    def blueprint_id(self) -> BlueprintId:
        """The blueprint's contract-id is it's own tx-id, this helper method just converts to the right type."""
        return blueprint_id_from_bytes(self.hash)

    def _load_blueprint_code_exec(
        self,
        executor: 'MeteredExecutor | None' = None,
    ) -> tuple[object, dict[str, object], SandboxCounts]:
        """XXX: DO NOT CALL THIS METHOD UNLESS YOU REALLY KNOW WHAT IT DOES.

        Loads and executes the blueprint code, capturing sandbox loading costs.

        Args:
            executor: A MeteredExecutor to use for loading. If None, a disabled
                     executor is created (no sandbox protection).

        Returns:
            A tuple of (blueprint_class, env, loading_costs) where loading_costs
            is a SandboxCounts with counter deltas (zero counts if sandbox not active).
        """
        from hathor.nanocontracts.metered_exec import MeteredExecutor

        if executor is None:
            executor = MeteredExecutor(config=DISABLED_CONFIG)
        loading_costs = SandboxCounts()

        try:
            with executor:  # start()/end() via context manager
                # Capture counts BEFORE exec to calculate delta
                before_counts: SandboxCounts | None = None
                if executor.config.enabled and hasattr(sys, 'sandbox'):
                    before_counts = SandboxCounts.capture()

                env = executor.exec(self.code.text)

                # Capture counts AFTER exec and calculate delta
                if executor.config.enabled and hasattr(sys, 'sandbox') and before_counts is not None:
                    after_counts = SandboxCounts.capture()
                    loading_costs = after_counts - before_counts
        except SandboxError as e:
            # Any sandbox limit exceeded (operations, iterations, memory, etc.)
            self.log.error('loading blueprint module failed, sandbox limit exceeded', error=str(e))
            raise OCBOutOfFuelDuringLoading from e

        blueprint_class = env[BLUEPRINT_EXPORT_NAME]
        return blueprint_class, env, loading_costs

    def _load_blueprint_code(
        self,
        executor: 'MeteredExecutor | None' = None,
    ) -> BlueprintCache:
        """This method loads the on-chain code (if not loaded) and returns the cached result.

        Args:
            executor: A MeteredExecutor to use for loading. If None, a disabled
                     executor is created (no sandbox protection).

        Returns:
            BlueprintCache containing the blueprint class, env, and loading costs.
        """
        if self._blueprint_cache is None:
            blueprint_class, env, loading_costs = self._load_blueprint_code_exec(executor)
            assert isinstance(blueprint_class, type)
            assert issubclass(blueprint_class, Blueprint)
            self._blueprint_cache = BlueprintCache(
                blueprint_class=blueprint_class,
                env=env,
                loading_costs=loading_costs,
            )
        return self._blueprint_cache

    def get_blueprint_object_bypass(self) -> object:
        """Loads the code and returns the object exported with @export"""
        blueprint_class, _, _ = self._load_blueprint_code_exec()
        return blueprint_class

    def get_blueprint_class(
        self,
        executor: 'MeteredExecutor | None' = None,
        skip_loading_cost: bool = False,
    ) -> type[Blueprint]:
        """Returns the blueprint class, applies loading cost to sandbox.

        When blueprint is cached AND sandbox is active, the cached loading costs
        are applied to ensure consistent cost regardless of cache state.

        Args:
            executor: A MeteredExecutor to use for loading. If None, a disabled
                     executor is created (no sandbox protection).
            skip_loading_cost: If True, skip applying cached loading costs. Used
                              to deduplicate loading costs when the same blueprint
                              is accessed multiple times in a single call chain.
        """
        was_cached = self._blueprint_cache is not None
        cache = self._load_blueprint_code(executor)

        # Apply cached costs when returning from cache with sandbox active
        sandbox_enabled = executor is not None and executor.config.enabled
        if was_cached and sandbox_enabled and cache.loading_costs and not skip_loading_cost:
            if hasattr(sys, 'sandbox') and sys.sandbox.enabled and not sys.sandbox.suspended:
                sys.sandbox.add_counts(**cache.loading_costs.to_dict())

        return cache.blueprint_class

    @property
    def loading_costs(self) -> SandboxCounts | None:
        """Return cached loading costs, or None if blueprint hasn't been loaded yet."""
        if self._blueprint_cache is None:
            return None
        return self._blueprint_cache.loading_costs or None

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

    def _serialize_ocb(self, *, skip_signature: bool = False) -> bytes:
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
