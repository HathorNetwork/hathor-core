"""In-process HathorManager harness — the reusable form of the CP-1 spike recipe.

IMPORTANT: importing this module has side effects (it selects the unittests network
and initialises the global reactor) and pulls in hathor + hathor_tests. Keep it out of
the `list`/`validate` paths; import it lazily (e.g. inside the CLI `run` handler).
"""
from __future__ import annotations

import os
import time

# Select the unittests network BEFORE importing anything from hathor.conf: low PoW
# weights + test-mode allowed, so REAL verifiers run cheaply.
from hathorlib.conf import UNITTESTS_SETTINGS_FILEPATH

os.environ.setdefault("HATHOR_CONFIG_YAML", UNITTESTS_SETTINGS_FILEPATH)

# The global reactor must exist before importing the test helpers (hathor_tests.utils
# builds an HDWallet at import time, which calls get_global_reactor).
from hathor.reactor import initialize_global_reactor

initialize_global_reactor(use_asyncio_reactor=True)

from hathor.daa import TestMode  # noqa: E402
from hathor.util import Random  # noqa: E402
from hathor_tests.dag_builder.builder import TestDAGBuilder  # noqa: E402
from hathor_tests.test_memory_reactor_clock import TestMemoryReactorClock  # noqa: E402
from hathor_tests.unittest import TestBuilder  # noqa: E402


class NodeHarness:
    """Builds a real in-process node: RocksDB temp-dir storage, REAL verifiers, and
    trivial (weight-1) PoW. Reproducible via `seed`. See RFC §"Standing up the node"."""

    def __init__(self, seed: int = 1234, trivial_pow: bool = True, shielded: bool = False) -> None:
        self.seed = seed
        self.trivial_pow = trivial_pow
        self.shielded = shielded
        self.clock: TestMemoryReactorClock | None = None
        self.manager = None
        self._artifacts = None

    def start(self) -> "NodeHarness":
        self.clock = TestMemoryReactorClock()
        # Anchor the virtual clock at a realistic wall time once (timestamps), then let
        # startup settle. NOTE: measurements use time.perf_counter(), not this clock.
        self.clock.advance(time.time())

        if self.shielded:
            # Enable shielded transactions via settings ONLY — keep the SAME real verifiers
            # and weight-1 PoW as the transparent harness, so shielded vs transparent timings
            # stay comparable (we deliberately do NOT swap in the simulator mining/verifiers,
            # which would skip verify_pow). Confirmed in CP-9: the feature flag alone suffices.
            import hathor.conf.get_settings as _gs
            from hathor.conf.settings import FeatureSetting
            # Also raise MAX_SERIALIZED_VERTEX_SIZE: a full-shielded output is ~5 KB at 64-bit, so a
            # tx with many of them exceeds the default 48 KB consensus cap. Benchmark-only override
            # (like the MAX_SHIELDED_OUTPUTS cap) so we can measure fat shielded txs.
            settings = _gs.get_global_settings().model_copy(update={
                "ENABLE_SHIELDED_TRANSACTIONS": FeatureSetting.ENABLED,
                "MAX_SERIALIZED_VERTEX_SIZE": 2_000_000,
            })
            # create_from_struct / vertex (de)serialization read the GLOBAL settings singleton, not the
            # builder's copy, so override the singleton too — otherwise fat shielded txs still hit the
            # 48 KB cap at (de)serialize. Process-wide and harmless for transparent runs.
            _gs._settings_singleton = _gs._settings_singleton._replace(settings=settings)
            builder = TestBuilder(settings)
        else:
            builder = TestBuilder()
        builder.set_rng(Random(self.seed)).set_reactor(self.clock)
        self._artifacts = builder.build()  # default storage = RocksDBStorage.create_temp()
        self.manager = self._artifacts.manager

        if self.trivial_pow:
            # weights -> 1 (only allowed on unittests/privatenet); verifiers stay REAL.
            self.manager.daa_factory.TEST_MODE = TestMode.TEST_ALL_WEIGHT

        self.manager.start()
        self.clock.run()
        self.clock.advance(5)
        return self

    def dag_builder(self) -> TestDAGBuilder:
        assert self.manager is not None, "call start() first"
        return TestDAGBuilder.from_manager(self.manager)

    @property
    def vertex_parser(self):
        return self.manager.vertex_parser

    @property
    def tx_storage(self):
        return self.manager.tx_storage

    def stop(self) -> None:
        if self.manager is not None:
            self.manager.stop()
        rocksdb = getattr(self._artifacts, "rocksdb_storage", None)
        if rocksdb is not None:
            rocksdb.close()  # release the temp-dir RocksDB

    def __enter__(self) -> "NodeHarness":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()
