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

from hathor_tps_bench.probes.cpuinfo import default_script_workers  # noqa: E402


def configure_logging(verbose: bool = False) -> None:
    """Filter the node's per-transaction DEBUG logging out of the timed pipeline.

    Nothing on the benchmark path ever called `structlog.configure` — that lives in `hathor_cli`,
    which the engine does not import — so structlog fell back to emitting EVERY level. The node
    then rendered a full transaction repr for every vertex inside `_post_consensus`, which the
    driver times as S6. The driver's `quiet=True` only downgrades info->debug; it does not skip
    the call, so nothing suppressed the render.

    Measured (N=400, W=60, 1i2o, 3 interleaved reps, medians): S6 226 us unconfigured -> 117 us
    filtered at INFO, i.e. ~110 us/tx of pure render+write inside a timed stage.

    A production node runs at INFO, so filtering is both faster AND more representative. Pass
    verbose=True to leave structlog untouched and reproduce the pre-fix numbers exactly (the
    Phase-1 / Phase-3 report figures were all collected that way).

    NOTE: a further ~46 us/tx remains in `_log_new_object`, which builds its kwargs
    (`get_metadata`, two `datetime.fromtimestamp`, `get_feature_states`) BEFORE testing the level,
    so that work happens even when the line is discarded. Fixing it means changing `hathor/`
    itself and is deliberately left upstream — see the checkpoint notes."""
    if verbose:
        return                      # leave structlog unconfigured == exactly the old behaviour
    import logging

    import structlog
    structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.INFO))


_rayon_workers_used: int | None = None


def _check_rayon_pool_reuse(workers: int) -> None:
    """Refuse to pretend a rust worker-count change took effect when it cannot.

    `htr-rs/crates/htr-lib/src/script/mod.rs` holds the rayon pool in a `OnceLock`: it is sized on
    first use and *"later calls with a different num_workers reuse the existing pool"*. So within
    one process the FIRST rust worker count wins forever.

    That matters because `report_data.run_cell` drives every cell and every repetition in a single
    process. A worker-count sweep written as several cells would therefore run every point at the
    first cell's thread count and draw a flat line — which reads as "threads don't help" rather
    than "the experiment was invalid". Failing loudly is the only safe behaviour; a sweep must use
    one PROCESS per worker count (the UI already runs one subprocess per run, and the CLI is one
    process per invocation)."""
    global _rayon_workers_used
    if _rayon_workers_used is None:
        _rayon_workers_used = workers
        return
    if _rayon_workers_used != workers:
        raise RuntimeError(
            f"rust script worker count cannot change within a process: the rayon pool was already "
            f"built with {_rayon_workers_used} worker(s) and this harness asked for {workers}. "
            f"The pool is a OnceLock in htr-lib, so the new value would be silently ignored and "
            f"the measurement would be wrong. Run one worker count per process instead "
            f"(one CLI invocation, or one UI run, per point)."
        )


class NodeHarness:
    """Builds a real in-process node: RocksDB temp-dir storage, REAL verifiers, and
    trivial (weight-1) PoW. Reproducible via `seed`. See RFC §"Standing up the node"."""

    def __init__(self, seed: int = 1234, trivial_pow: bool = True, shielded: bool = False,
                 opt: dict[str, bool] | None = None, sync_precompute: bool = False,
                 verbose_logs: bool = False, script_mode: str = "rust",
                 script_workers: int | None = None, script_min_inputs: int = 4) -> None:
        self.seed = seed
        self.trivial_pow = trivial_pow
        self.shielded = shielded
        # Input-script verification pool — the knobs for the single-thread vs multi-core axis.
        #   script_mode: disabled | threads | processes | rust | shadow-rust
        #   script_workers: pool size; None = auto -> PHYSICAL cores. Sizing from logical cores
        #     oversubscribes: on the reference 4-physical/8-logical machine, 8 workers measured
        #     ~2x WORSE than 4, because rayon then claims every thread and preempts the
        #     single-threaded driver and RocksDB's compaction. In rust mode this sizes the rayon
        #     pool (see the one-pool-per-process caveat in _check_rayon_pool_reuse).
        #   script_min_inputs: below this many inputs the threads/processes modes run serially
        #     rather than pay fan-out overhead. The rust modes ignore it (run_jobs docstring:
        #     "the batch call is a single in-process call, so it wins even at one input").
        self.script_mode = script_mode
        # Resolved eagerly so the effective value is recorded and printed, not left as "auto".
        self.script_workers = (default_script_workers() if script_workers is None
                               else script_workers)
        self.script_workers_auto = script_workers is None
        self.script_min_inputs = script_min_inputs
        # False (default) filters the node's per-tx DEBUG render out of timed S6; True restores
        # the pre-fix behaviour for reproducing the published figures. See configure_logging().
        self.verbose_logs = verbose_logs
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
        # Logging first: it must be filtered before any vertex is processed, or the build itself
        # renders a repr per funding vertex (and S6 would carry it for the measured txs).
        configure_logging(self.verbose_logs)

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
        if self.opt.get("s3s4", True) and self.script_mode != "disabled" and self.script_workers > 0:
            from hathor.verification.script_verification_pool import ScriptVerificationMode, ScriptVerificationPool
            mode = ScriptVerificationMode(self.script_mode)
            if mode in (ScriptVerificationMode.RUST, ScriptVerificationMode.SHADOW_RUST):
                _check_rayon_pool_reuse(self.script_workers)
            self._script_pool = ScriptVerificationPool(
                mode=mode, num_workers=self.script_workers, min_inputs=self.script_min_inputs)
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
