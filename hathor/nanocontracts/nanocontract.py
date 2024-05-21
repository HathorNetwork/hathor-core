# Copyright 2023 Hathor Labs
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

from collections import defaultdict
from typing import TYPE_CHECKING, Any, NamedTuple, Optional, Type

from structlog import get_logger
from typing_extensions import override

from hathor.conf.get_settings import get_global_settings
from hathor.crypto.util import get_address_b58_from_public_key_bytes, get_address_from_public_key_bytes
from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.method_parser import NCMethodParser
from hathor.nanocontracts.runner import Runner
from hathor.nanocontracts.types import Context, NCAction, NCActionType
from hathor.transaction import Transaction, TxInput, TxOutput, TxVersion
from hathor.transaction.util import VerboseCallback, int_to_bytes, unpack, unpack_len

if TYPE_CHECKING:
    from hathor.nanocontracts.storage import NCBaseStorage  # noqa: F401
    from hathor.transaction.storage import TransactionStorage  # noqa: F401

logger = get_logger()

NC_VERSION = 1
NC_INITIALIZE_METHOD = 'initialize'


class NCCallInfo(NamedTuple):
    """This tuple carries the pieces of information serialized inside transactions."""
    version: int
    id: bytes
    method: str
    args_bytes: bytes
    pubkey: bytes
    signature: bytes


class NanoContract(Transaction):
    """NanoContract vertex to be placed on the DAG of transactions."""

    MIN_NUM_INPUTS = 0

    def __init__(self,
                 nonce: int = 0,
                 timestamp: Optional[int] = None,
                 version: TxVersion = TxVersion.NANO_CONTRACT,
                 weight: float = 0,
                 inputs: Optional[list[TxInput]] = None,
                 outputs: Optional[list[TxOutput]] = None,
                 parents: Optional[list[bytes]] = None,
                 tokens: Optional[list[bytes]] = None,
                 hash: Optional[bytes] = None,
                 storage: Optional['TransactionStorage'] = None) -> None:
        super().__init__(nonce=nonce, timestamp=timestamp, version=version, weight=weight, inputs=inputs,
                         outputs=outputs or [], tokens=tokens, parents=parents or [], hash=hash, storage=storage)

        self._settings = get_global_settings()
        if not self._settings.ENABLE_NANO_CONTRACTS:
            raise RuntimeError('NanoContracts are disabled')

        # nc_id equals to the blueprint_id when a Nano Contract is being created.
        # nc_id equals to the nanocontract_id when a method is being called.
        self.nc_id: bytes = b''

        # Name of the method to be called. When creating a new Nano Contract, it must be equal to 'initialize'.
        self.nc_method: str = ''

        # Serialized arguments to nc_method.
        self.nc_args_bytes: bytes = b''

        # Pubkey and signature of the transaction owner / caller.
        self.nc_pubkey: bytes = b''
        self.nc_signature: bytes = b''

        # Cache.
        self._blueprint_class: Optional[Type[Blueprint]] = None

    def get_nanocontract_id(self) -> bytes:
        """Return the contract id."""
        if self.nc_method == NC_INITIALIZE_METHOD:
            assert self.hash is not None
            return self.hash
        return self.nc_id

    def get_blueprint_class(self) -> Type[Blueprint]:
        """Return the blueprint class of the contract."""
        assert self.storage is not None
        assert self.storage.nc_catalog is not None
        if self._blueprint_class is not None:
            return self._blueprint_class

        blueprint_id = self.get_blueprint_id()
        blueprint_class = self.storage.nc_catalog.get_blueprint_class(blueprint_id)
        self._blueprint_class = blueprint_class
        return blueprint_class

    def get_blueprint_id(self) -> bytes:
        """Return the blueprint id."""
        assert self.storage is not None
        assert self.storage.nc_catalog is not None
        if self.nc_method == NC_INITIALIZE_METHOD:
            return self.nc_id
        else:
            nanocontract_id = self.nc_id
            nanocontract = self.storage.get_transaction(nanocontract_id)
            assert isinstance(nanocontract, NanoContract)
            assert nanocontract.nc_method == NC_INITIALIZE_METHOD
            return nanocontract.nc_id

    def execute(self, nc_storage: 'NCBaseStorage') -> None:
        """Execute the contract's method call."""
        blueprint_class = self.get_blueprint_class()
        method = getattr(blueprint_class, self.nc_method)
        parser = NCMethodParser(method)
        args = parser.parse_args_bytes(self.nc_args_bytes)

        context = self.get_context()
        self.call_public_method(nc_storage, self.nc_method, context, *args)

    def get_runner(self, nc_storage: 'NCBaseStorage') -> Runner:
        """Return a Runner object."""
        blueprint_class = self.get_blueprint_class()
        nc_id = self.get_nanocontract_id()
        return Runner(blueprint_class, nc_id, nc_storage)

    def call_private_method(self, nc_storage: 'NCBaseStorage', method_name: str, *args: Any) -> Any:
        """Utility method to call the blueprint's method."""
        runner = self.get_runner(nc_storage)
        return runner.call_private_method(method_name, *args)

    def call_public_method(self, nc_storage: 'NCBaseStorage', method_name: str, ctx: Context, *args: Any) -> None:
        """Utility method to call the blueprint's method."""
        runner = self.get_runner(nc_storage)
        runner.call_public_method(method_name, ctx, *args)

    def get_context(self) -> Context:
        """Return a context to be used in a method call."""
        diff_by_token: defaultdict[bytes, int] = defaultdict(int)

        for txin in self.inputs:
            assert self.storage is not None
            spent_tx = self.storage.get_transaction(txin.tx_id)
            spent_txout = spent_tx.outputs[txin.index]
            token_uid = spent_tx.get_token_uid(spent_txout.get_token_index())
            diff_by_token[token_uid] += spent_txout.value

        for txout in self.outputs:
            token_uid = self.get_token_uid(txout.get_token_index())
            diff_by_token[token_uid] -= txout.value

        tokens = set(diff_by_token.keys())

        action_list = []
        for token_uid in tokens:
            diff = diff_by_token[token_uid]

            if diff == 0:
                continue
            elif diff < 0:
                action = NCActionType.WITHDRAWAL
                amount = -diff
            else:
                # diff > 0:
                action = NCActionType.DEPOSIT
                amount = diff
            assert amount >= 0
            action_list.append(NCAction(action, token_uid, amount))

        meta = self.get_metadata()
        timestamp: int
        if meta.first_block is None:
            # XXX Which timestamp to use when it is on mempool?
            timestamp = self.timestamp
        else:
            assert self.storage is not None
            first_block = self.storage.get_transaction(meta.first_block)
            timestamp = first_block.timestamp

        address = get_address_from_public_key_bytes(self.nc_pubkey)
        context = Context(
            actions=action_list,
            tx=self,
            address=address,
            timestamp=timestamp,
        )
        return context

    ################################
    # Methods for Transaction
    ################################

    def get_related_addresses(self) -> set[str]:
        ret = super().get_related_addresses()
        ret.add(get_address_b58_from_public_key_bytes(self.nc_pubkey))
        return ret

    def get_funds_fields_from_struct(self, buf: bytes, *, verbose: VerboseCallback = None) -> bytes:
        buf = super().get_funds_fields_from_struct(buf, verbose=verbose)

        call_info, buf = NanoContract.deserialize_method_call(buf, verbose=verbose)
        self.nc_id = call_info.id
        self.nc_method = call_info.method
        self.nc_args_bytes = call_info.args_bytes
        self.nc_pubkey = call_info.pubkey
        self.nc_signature = call_info.signature

        return buf

    def get_funds_struct(self) -> bytes:
        struct_bytes = super().get_funds_struct()
        struct_bytes += self.serialize_method_call()
        return struct_bytes

    def get_sighash_all(self, *, skip_cache: bool = False) -> bytes:
        if not skip_cache and self._sighash_cache:
            return self._sighash_cache
        struct_bytes = super().get_sighash_all(skip_cache=True)
        struct_bytes += self.serialize_method_call(skip_signature=True)
        self._sighash_cache = struct_bytes
        return struct_bytes

    @classmethod
    def deserialize_method_call(cls, buf: bytes, *, verbose: VerboseCallback = None) -> tuple[NCCallInfo, bytes]:
        """Deserialize method call information from a serialized transaction."""
        (nc_version,), buf = unpack('!B', buf)
        if verbose:
            verbose('nc_version', nc_version)
        if nc_version != NC_VERSION:
            raise ValueError('unknown nanocontract version: {}'.format(nc_version))

        nc_id, buf = unpack_len(32, buf)
        if verbose:
            verbose('nc_id', nc_id)
        (nc_method_len,), buf = unpack('!B', buf)
        if verbose:
            verbose('nc_method_len', nc_method_len)
        nc_method, buf = unpack_len(nc_method_len, buf)
        if verbose:
            verbose('nc_method', nc_method)
        (nc_args_bytes_len,), buf = unpack('!H', buf)
        if verbose:
            verbose('nc_args_bytes_len', nc_args_bytes_len)
        nc_args_bytes, buf = unpack_len(nc_args_bytes_len, buf)
        if verbose:
            verbose('nc_args_bytes', nc_args_bytes)
        (nc_pubkey_len,), buf = unpack('!B', buf)
        if verbose:
            verbose('nc_pubkey_len', nc_pubkey_len)
        nc_pubkey, buf = unpack_len(nc_pubkey_len, buf)
        if verbose:
            verbose('nc_pubkey', nc_pubkey)
        (nc_signature_len,), buf = unpack('!B', buf)
        if verbose:
            verbose('nc_signature_len', nc_signature_len)
        nc_signature, buf = unpack_len(nc_signature_len, buf)
        if verbose:
            verbose('nc_signature', nc_signature)

        decoded_nc_method = nc_method.decode('ascii')

        return NCCallInfo(
            version=nc_version,
            id=nc_id,
            method=decoded_nc_method,
            args_bytes=nc_args_bytes,
            pubkey=nc_pubkey,
            signature=nc_signature,
        ), buf

    def serialize_method_call(self, *, skip_signature: bool = False) -> bytes:
        """Serialize the method call as part of a transaction serialization."""
        encoded_method = self.nc_method.encode('ascii')

        ret = []
        ret.append(int_to_bytes(NC_VERSION, 1))
        ret.append(self.nc_id)
        ret.append(int_to_bytes(len(self.nc_method), 1))
        ret.append(encoded_method)
        ret.append(int_to_bytes(len(self.nc_args_bytes), 2))
        ret.append(self.nc_args_bytes)
        ret.append(int_to_bytes(len(self.nc_pubkey), 1))
        ret.append(self.nc_pubkey)
        if not skip_signature:
            ret.append(int_to_bytes(len(self.nc_signature), 1))
            ret.append(self.nc_signature)
        else:
            ret.append(int_to_bytes(0, 1))
        return b''.join(ret)

    @override
    def get_minimum_number_of_inputs(self) -> int:
        return 0

    def to_json(self, decode_script: bool = False, include_metadata: bool = False) -> dict[str, Any]:
        json = super().to_json(decode_script=decode_script, include_metadata=include_metadata)
        json['nc_id'] = self.get_nanocontract_id().hex()
        json['nc_blueprint_id'] = self.get_blueprint_id().hex()
        json['nc_method'] = self.nc_method
        json['nc_args'] = self.nc_args_bytes.hex()
        json['nc_pubkey'] = self.nc_pubkey.hex()
        return json

    def to_json_extended(self) -> dict[str, Any]:
        json = self.to_json()
        json_extended = super().to_json_extended()
        return {**json, **json_extended}
