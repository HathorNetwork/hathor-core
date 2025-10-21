from typing import Any

from hathor.conf.settings import HathorSettings
from hathor.manager import HathorManager
from hathor.nanocontracts import Blueprint, NCRocksDBStorageFactory
from hathor.nanocontracts.method import Method
from hathor.nanocontracts.nc_exec_logs import NCExecEntry, NCLogConfig
from hathor.nanocontracts.runner import Runner
from hathor.nanocontracts.storage import NCBlockStorage
from hathor.nanocontracts.storage.backends import RocksDBNodeTrieStore
from hathor.nanocontracts.storage.patricia_trie import PatriciaTrie
from hathor.nanocontracts.utils import sign_pycoin
from hathor.reactor import ReactorProtocol
from hathor.transaction import Transaction
from hathor.transaction.headers.nano_header import NanoHeader, NanoHeaderAction
from hathor.transaction.storage import TransactionRocksDBStorage, TransactionStorage
from hathor.types import VertexId
from hathor.util import not_none
from hathor.wallet import HDWallet


class TestRunner(Runner):
    __test__ = False

    def __init__(
        self,
        *,
        tx_storage: TransactionStorage,
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
        super().__init__(
            tx_storage=tx_storage,
            storage_factory=storage_factory,
            block_storage=block_storage,
            settings=settings,
            reactor=reactor,
            seed=seed,
        )


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
