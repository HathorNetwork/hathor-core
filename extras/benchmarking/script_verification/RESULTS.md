# Script verification benchmark — results & decision

Measured with `benchmark_script_verification.py` on a 24-core machine (CPython 3.13, `cryptography` 42.x),
opcodes V2, median wall time over many iterations.

## Headline finding (inverts the original hypothesis)

`cryptography`'s `public_key.verify()` (OpenSSL ECDSA) does **not** release the GIL in this version. So:

- **Threads never help and usually hurt.** With >2 workers they thrash on the GIL — e.g. 32 p2pkh inputs go from
  11 ms serial to 27 ms (4 threads) / 57 ms (8 threads). At best (2 workers) they match serial.
- **Processes give real, growing speedup**, because each worker is a separate interpreter with its own GIL.
- **The detached payload is free**: the serial loop over `execute_script_verification_job` matches today's
  `script_eval` within noise (~1.00–1.03x). The refactor adds no overhead.

## Process pool — speedup vs serial (4 workers unless noted)

| inputs | p2pkh | multisig |
|-------:|------:|---------:|
|   1    | 0.63x | 0.79x |
|   2    | 0.96x | 1.31x |
|   3    | 0.97x | 0.99x |
|   4    | 1.40x | 1.66x |
|   6    | 1.39x | 2.21x |
|   8    | 1.56x | 1.95x |
|  16    | 1.93x | 2.60x |
|  32    | 2.07x (3.23x @8w) | 3.35x (3.48x @8w) |
| 255    | 2.84x (3.22x @8w) | 3.50x (6.02x @8w) |

## Decision

- **Executor kind (when enabled): `process`.** Threads stay available behind the flag (cheap to keep; may behave
  differently on a future free-threaded/no-GIL CPython) but are never recommended on current CPython.
- **`min_inputs = 4`.** The crossover is crisp: 3 inputs is break-even (~0.97–0.99x), 4 inputs is the first solid
  win (1.40x / 1.66x). Transactions with 1–3 inputs (the common case) run inline serially with zero overhead.
- **`num_workers = 4`** default. 8 workers only pays off for very large (32–255 input) consolidation txs; operators
  can raise it.
- Ship **default OFF** first; flip the default on after a testnet soak.

Reproduce: `uv run python extras/benchmarking/script_verification/benchmark_script_verification.py`

## Rust arm (htr_lib.verify_scripts_batch — in-process rayon, libsecp256k1)

Same machine/method as above (24 cores, CPython 3.13, repeat=50, rayon pool sized to 8 workers). The Rust arm
is one GIL-released batch call: no pickling, no IPC, no subprocess spawn, and `libsecp256k1` verifies several
times faster per signature than OpenSSL's generic ECDSA.

### Speedup vs serial (and vs the best process-pool cell)

| inputs | p2pkh rust | p2pkh best process | multisig rust | multisig best process |
|-------:|-----------:|-------------------:|--------------:|----------------------:|
|   1    | **10.9x**  | 0.36x | **6.3x**  | 0.37x |
|   2    | **8.2x**   | 0.78x | **14.7x** | 1.31x |
|   8    | **12.1x**  | 2.51x | **20.7x** | 2.86x |
|  32    | **16.2x**  | 2.51x | **53.2x** | 3.61x |
| 255    | **58.2x**  | 3.99x | **45.3x** | 3.05x |

Per-input cost drops from ~320 µs (serial p2pkh) to ~5–40 µs, and from ~780 µs (serial 2-of-3 multisig)
to ~15–130 µs.

### Findings

- **Rust wins everywhere, including the 1-input case** the process pool loses (10.9x vs 0.36x at 1 p2pkh
  input). There is no crossover: the `RUST` mode runs with `min_inputs` gating disabled.
- **Rust beats the process pool's best cell by 5–15x** at every size; the gap *grows* with input count
  (no serial dispatch thread, no oversubscription cliff).
- Correctness is enforced by the differential suite in `hathor_tests/tx/test_rust_script_verification.py`
  (corpus + mutations + hypothesis fuzz + DER-acceptance fuzz, zero category mismatches) and by the
  `shadow-rust` executor for live soak.
- **Recommendation:** `--script-verification-executor rust` (with `--script-verification-workers` sizing the
  rayon pool) once the testnet shadow soak is clean; the process/thread modes remain behind the flag as
  fallback.
