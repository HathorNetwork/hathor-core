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
