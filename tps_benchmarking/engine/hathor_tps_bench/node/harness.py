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

    def __init__(self, seed: int = 1234, trivial_pow: bool = True, shielded: bool = False,
                 opt: dict[str, bool] | None = None, sync_precompute: bool = False) -> None:
        self.seed = seed
        self.trivial_pow = trivial_pow
        self.shielded = shielded
        # Opt-in sync-path mode: when set (and s3s4 on), swap in RustVerificationService so a batch
        # driver can call precompute_stateless_batch (the fused Rust pipeline). Off by default — the
        # standard --opt path keeps the bare script-pool (verified). See deferred-sync-path doc.
        self.sync_precompute = sync_precompute
        # Per-section optimization gating (PR #1729 merge). Keys s1,s2,s3s4,s5,s6 → True=optimized
        # (default), False=baseline. Resolved from --opt/--no-opt in the CLI. Default = all ON.
        self.opt = opt if opt is not None else {s: True for s in ("s1", "s2", "s3s4", "s5", "s6")}
        self.clock: TestMemoryReactorClock | None = None
        self.manager = None
        self._artifacts = None
        self._script_pool = None  # S3S4: Rust script-verification pool, attached when opt['s3s4']
        self.rust_service = None  # sync-path: RustVerificationService, set when sync_precompute

    def start(self) -> "NodeHarness":
        # Export the per-section optimization gating to env BEFORE building the node, so the gated
        # hathor-core sites (read via hathor.opt_flags.opt_enabled) pick it up. HATHOR_OPT_<S>=1
        # optimized / 0 baseline. cache_clear() handles multiple harnesses in one process.
        for _s, _on in self.opt.items():
            os.environ[f"HATHOR_OPT_{_s.upper()}"] = "1" if _on else "0"
        from hathor.opt_flags import opt_enabled
        opt_enabled.cache_clear()

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

        # ---- OPTIMIZATION GATING WIRING (PR #1729 merge) -------------------------------------
        # TODO(opt-merge step 4): translate self.opt[...] into builder/settings choices, per section:
        #   s3s4 -> builder.set_script_verification_config(mode=RUST if opt else PROCESS/serial, ...)
        #           (reuse the upstream executor switch under our naming; picks RustVerificationService
        #            vs the pure-Python VerificationService at builder.py:600-621)
        #   s5   -> select storage backend (Rust htr_lib.RocksDb vs python-rocksdb) + binary-vs-JSON
        #           metadata serde + the mempool-tips / save-dedup / WriteBatch consensus toggles.
        #           Fresh temp-dir per run, so the on-disk format choice is safe to flip per run.
        #   s1   -> gate the Rust vertex-parser fast path (_vertex_parser.deserialize dispatcher).
        #   s2   -> gate the get_transaction read fast-paths (LRU/scope-fusion/miss-probe).
        #   s6   -> gate drop-2nd-validate_full + info-index write-on-change + reactor-yield batching.
        # TODO(opt-merge future): add per-optimization SUB-FLAGS (esp. S5: --mem-tips/--save-dedup/
        #   --write-batch/--binary-metadata/--rust-storage/--reorg-gate; S3S4: --rust-scripts vs
        #   --parallel-scripts). For now a section flag toggles ALL of its optimizations together.
        # No behavior is gated yet — self.opt is threaded and ready for step-4 wiring.
        builder.set_rng(Random(self.seed)).set_reactor(self.clock)
        self._artifacts = builder.build()  # default storage = RocksDBStorage.create_temp()
        self.manager = self._artifacts.manager

        if self.trivial_pow:
            # weights -> 1 (only allowed on unittests/privatenet); verifiers stay REAL.
            self.manager.daa_factory.TEST_MODE = TestMode.TEST_ALL_WEIGHT

        self.manager.start()

        # S3S4 OPTIMIZATION (PR #1729): when enabled, attach a Rust script-verification pool to the tx
        # verifier so per-input script (ECDSA) checks run in Rust (htr_lib, GIL released). Transparent
        # txs use it; shielded txs fall back to the serial shielded path via the dispatcher. The per-tx
        # driver does not use the batch stateless-precompute (that helps block sync), so the pool alone
        # delivers the s3s4 win here. Baseline (--no-opt s3s4): no pool -> serial Python verification.
        if self.opt.get("s3s4", True):
            from hathor.verification.script_verification_pool import ScriptVerificationMode, ScriptVerificationPool
            self._script_pool = ScriptVerificationPool(mode=ScriptVerificationMode.RUST, num_workers=4, min_inputs=4)
            self._script_pool.start()
            self.manager.verification_service.verifiers.tx._script_verification_pool = self._script_pool

            # Sync-path mode (opt-in): swap in RustVerificationService, which can precompute a whole
            # batch's stateless+script verification in one GIL-released Rust call. validate_full
            # delegates to super when no precompute ran, so per-tx behavior is unchanged otherwise.
            if self.sync_precompute:
                from hathor.verification.rust_verification_service import RustVerificationService
                base = self.manager.verification_service
                self.rust_service = RustVerificationService(
                    settings=base._settings, verifiers=base.verifiers,
                    tx_storage=self.manager.tx_storage, nc_storage_factory=base._nc_storage_factory,
                    script_verification_pool=self._script_pool,
                )
                self.manager.verification_service = self.rust_service
                self.manager.vertex_handler._verification_service = self.rust_service

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
        if self._script_pool is not None:
            self._script_pool.stop()
        if self.manager is not None:
            self.manager.stop()
        rocksdb = getattr(self._artifacts, "rocksdb_storage", None)
        if rocksdb is not None:
            rocksdb.close()  # release the temp-dir RocksDB

    def __enter__(self) -> "NodeHarness":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()
