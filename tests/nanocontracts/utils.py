
from hathor.conf.settings import HathorSettings
from hathor.manager import HathorManager
from hathor.nanocontracts.nc_exec_logs import NCLogConfig
from hathor.nanocontracts.runner import Runner
from hathor.nanocontracts.storage import NCBlockStorage, NCStorageFactory
from hathor.reactor import ReactorProtocol
from hathor.transaction.storage import TransactionStorage
from hathor.types import VertexId
from hathor.util import not_none


class TestRunner(Runner):
    __test__ = False

    def __init__(
        self,
        tx_storage: TransactionStorage,
        storage_factory: NCStorageFactory,
        block_storage: NCBlockStorage,
        *,
        settings: HathorSettings,
        reactor: ReactorProtocol,
        seed: bytes | None = None,
    ) -> None:
        if seed is None:
            seed = b'x' * 32
        super().__init__(
            tx_storage=tx_storage,
            storage_factory=storage_factory,
            block_storage=block_storage,
            settings=settings,
            reactor=reactor,
            seed=seed,
        )


def assert_nc_failure_reason(*, manager: HathorManager, tx_id: VertexId, block_id: VertexId, reason: str) -> None:
    """A function to assert NCFail reason in tests by inspecting NC logs."""
    nc_log_storage = manager.consensus_algorithm.block_algorithm_factory.nc_log_storage
    assert nc_log_storage._config in {NCLogConfig.ALL, NCLogConfig.FAILED}, (
        'to assert NCFail reason, NC logs must be enabled'
    )
    logs = not_none(nc_log_storage.get_logs(tx_id, block_id=block_id))
    failure_entry = logs.entries[block_id][-1]
    assert failure_entry.error_traceback is not None, 'no error found'
    assert reason in failure_entry.error_traceback, (
        f'reason not found in nano error traceback\n\n'
        f'expected: "{reason}"\n'
        f'found:\n\n'
        f'{failure_entry.error_traceback}'
    )
