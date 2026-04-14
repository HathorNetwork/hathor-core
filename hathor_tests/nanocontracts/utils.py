from typing import Any

from hathor.conf.settings import HathorSettings
from hathor.manager import HathorManager
from hathor.nanocontracts import Blueprint, Context, NCRocksDBStorageFactory
from hathor.nanocontracts.blueprint_service import BlueprintService
from hathor.nanocontracts.method import Method
from hathor.nanocontracts.nc_exec_logs import NCExecEntry, NCLogConfig
from hathor.nanocontracts.runner import CallInfo, Runner
from hathor.nanocontracts.storage import NCBlockStorage, NCContractStorage
from hathor.nanocontracts.storage.backends import RocksDBNodeTrieStore
from hathor.nanocontracts.storage.contract_storage import Balance
from hathor.nanocontracts.storage.patricia_trie import PatriciaTrie
from hathor.nanocontracts.types import BlueprintId, ContractId, NCArgs, TokenUid
from hathor.nanocontracts.utils import sign_pycoin
from hathor.reactor import ReactorProtocol
from hathor.transaction import Transaction
from hathor.transaction.headers.nano_header import NanoHeader, NanoHeaderAction
from hathor.transaction.storage import TransactionRocksDBStorage
from hathor.types import VertexId
from hathor.util import not_none
from hathor.wallet import HDWallet
from hathorlib.nanocontracts.tx_storage_protocol import NCTransactionStorageProtocol
from hathorlib.nanocontracts.versions import NanoRuntimeVersion


class TestRunner:
    """Limited test-facing wrapper around `Runner`."""

    __test__ = False
    MAX_RECURSION_DEPTH = Runner.MAX_RECURSION_DEPTH
    MAX_CALL_COUNTER = Runner.MAX_CALL_COUNTER

    def __init__(
        self,
        *,
        runtime_version: NanoRuntimeVersion,
        tx_storage: NCTransactionStorageProtocol,
        blueprint_service: BlueprintService,
        settings: HathorSettings,
        reactor: ReactorProtocol,
        seed: bytes | None = None,
    ) -> None:
        if seed is None:
            seed = b'x' * 32
        assert isinstance(tx_storage, TransactionRocksDBStorage)
        storage_factory = NCRocksDBStorageFactory(tx_storage._rocksdb_storage)
        store = RocksDBNodeTrieStore(tx_storage._rocksdb_storage)
        block_trie = PatriciaTrie(store)
        block_storage = NCBlockStorage(block_trie)
        self._runner: Runner = Runner(
            runtime_version=runtime_version,
            tx_storage=tx_storage,
            blueprint_service=blueprint_service,
            storage_factory=storage_factory,
            block_storage=block_storage,
            settings=settings,
            reactor=reactor,
            seed=seed,
        )

    def create_contract(
        self,
        contract_id: ContractId,
        blueprint_id: BlueprintId,
        ctx: Context,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        return self._runner.create_contract(contract_id, blueprint_id, ctx, *args, **kwargs)

    def create_contract_with_nc_args(
        self,
        contract_id: ContractId,
        blueprint_id: BlueprintId,
        ctx: Context,
        nc_args: NCArgs,
    ) -> Any:
        return self._runner.create_contract_with_nc_args(contract_id, blueprint_id, ctx, nc_args)

    def call_public_method(
        self,
        contract_id: ContractId,
        method_name: str,
        ctx: Context,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        return self._runner.call_public_method(contract_id, method_name, ctx, *args, **kwargs)

    def call_public_method_with_nc_args(
        self,
        contract_id: ContractId,
        method_name: str,
        ctx: Context,
        nc_args: NCArgs,
    ) -> Any:
        return self._runner.call_public_method_with_nc_args(contract_id, method_name, ctx, nc_args)

    def call_view_method(self, contract_id: ContractId, method_name: str, *args: Any, **kwargs: Any) -> Any:
        return self._runner.call_view_method(contract_id, method_name, *args, **kwargs)

    def get_current_balance(self, contract_id: ContractId, token_uid: TokenUid | None) -> Balance:
        return self._runner.get_current_balance(contract_id, token_uid)

    def get_last_call_info(self) -> CallInfo:
        return self._runner.get_last_call_info()

    def get_storage(self, contract_id: ContractId) -> NCContractStorage:
        return self._runner.get_storage(contract_id)

    def has_contract_been_initialized(self, contract_id: ContractId) -> bool:
        return self._runner.has_contract_been_initialized(contract_id)


def get_nc_failure_entry(*, manager: HathorManager, tx_id: VertexId, block_id: VertexId) -> NCExecEntry:
    """Return the failure entry for a nano execution."""
    nc_log_storage = manager.consensus_algorithm.block_algorithm_factory.nc_log_storage
    assert nc_log_storage._config in {NCLogConfig.ALL, NCLogConfig.FAILED}, (
        'to get NCFail reason, NC logs must be enabled'
    )
    logs = not_none(nc_log_storage.get_logs(tx_id, block_id=block_id))
    return logs.entries[block_id][-1]


def assert_nc_failure_reason(*, manager: HathorManager, tx_id: VertexId, block_id: VertexId, reason: str) -> None:
    """A function to assert NCFail reason in tests by inspecting NC logs."""
    failure_entry = get_nc_failure_entry(manager=manager, tx_id=tx_id, block_id=block_id)
    assert failure_entry.error_traceback is not None, 'no error found'
    assert reason in failure_entry.error_traceback, (
        f'reason not found in nano error traceback\n\n'
        f'expected: "{reason}"\n'
        f'found:\n\n'
        f'{failure_entry.error_traceback}'
    )


def set_nano_header(
    *,
    tx: Transaction,
    wallet: HDWallet,
    nc_id: VertexId,
    nc_actions: list[NanoHeaderAction] | None = None,
    nc_method: str | None = None,
    nc_args: tuple[Any, ...] | None = None,
    blueprint: type[Blueprint] | None = None,
    seqnum: int = 1,
) -> None:
    """Configure a nano header for a tx."""
    assert len(tx.headers) == 0
    privkey = wallet.get_key_at_index(0)

    nc_args_bytes = b'\x00'
    if nc_args is not None:
        assert nc_method is not None
        method_parser = Method.from_callable(getattr(blueprint, nc_method))
        nc_args_bytes = method_parser.serialize_args_bytes(nc_args)

    nano_header = NanoHeader(
        tx=tx,
        nc_seqnum=seqnum,
        nc_id=nc_id,
        nc_method=nc_method if nc_method is not None else 'nop',
        nc_args_bytes=nc_args_bytes,
        nc_address=b'',
        nc_script=b'',
        nc_actions=nc_actions if nc_actions is not None else [],
    )

    sign_pycoin(nano_header, privkey)
    tx.headers.append(nano_header)
