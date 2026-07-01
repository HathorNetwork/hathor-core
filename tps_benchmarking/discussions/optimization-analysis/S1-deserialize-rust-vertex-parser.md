# S1 — Deserialize: the Rust vertex parser

> **What S1 is:** the very first pipeline stage — take the raw wire bytes that arrived over
> the p2p network and turn them into a Python vertex object (`Block` / `Transaction` /
> `TokenCreationTransaction`). In our benchmark this is the `vertex_parser.deserialize(tx_bytes)`
> call.
>
> **Bottom line up front:** S1 is **not** a real bottleneck (parsing is ~0.78 µs/tx, and *all*
> Rust-side verification is ~2% of the ~640 µs/tx budget). This change is a low-risk,
> exactness-preserving migration whose real value is (a) computing the tx **hash** natively in
> the same pass and (b) feeding the larger fused parse+verify Rust pipeline. Treat it as
> plumbing, not a hotspot fix. All citations are to the PR clone at `optimized-ref/`.

---

## 1. What changed

**Before (pure Python):** `VertexParser.deserialize()` read the version byte, picked the
subclass, and called `create_from_struct(...)`, which walks the bytes field-by-field in Python
(`struct.unpack`, slicing, boxing each field into a Python object). That code still exists,
now renamed `_deserialize_python` and labelled *"the authoritative Python parser (consensus
reference)"* (`hathor/transaction/vertex_parser/_vertex_parser.py:72-91`).

**After (Rust fast path + Python fallback):** `deserialize()` is now a two-line dispatcher —
try Rust, fall back to Python:

```python
# _vertex_parser.py:65-70
def deserialize(self, data: bytes, storage=None) -> BaseTransaction:
    vertex = self._deserialize_rust(data, storage)
    if vertex is not None:
        return vertex
    return self._deserialize_python(data, storage)
```

The Rust side is exposed as a `#[pyfunction]` registered into the `htr_lib` module
(`htr-rs/crates/htr-lib/src/lib.rs:34-35`). Critically, **Rust does not build Python vertex
objects.** It parses the bytes into a flat tuple of primitives and `bytes`, and Python
re-assembles the actual object. The FFI contract (in the type stub `htr_lib.pyi:32-46`) returns
`version, signal_bits, weight, timestamp, nonce, hash, parents, tokens, inputs, outputs, block_data,
token_info` — or `None` for anything Rust declines to handle (which triggers the Python fallback).

Two supporting changes in `base_transaction.py`: a new `_origin_bytes` slot (`:145`, set at
`:191`) caches `(hash, wire_bytes)` so a network-parsed vertex is **never re-serialized**
downstream, and `get_serialized_size()` (`:434-439`) returns `len(origin_bytes)` instead of
re-serializing. (The slot is populated in `RustVerificationService.verify_bytes`, not the parser.)

## 2. How it works (bytes → struct)

**Rust side (`vertex/mod.rs`):** a tiny cursor `Reader` (`:68-112`) borrows the byte slice and
reads big-endian, **bounds-checked** fields — `take(n)` does `checked_add` and returns `None`
past the end, so it physically cannot read past a truncated buffer. `parse()` (`:204-292`):
1. read `signal_bits` + `version`;
2. **dispatch on version** — block (0), transaction (1), token-creation (2); **any other
   version → `return None`** (merge-mined/PoA/on-chain-blueprint go to Python, `:250`);
3. parse funds region, then graph (weight/timestamp/parents), then nonce;
4. **trailing-bytes guard:** `if !r.is_empty() { return None }` (`:270`) — if bytes remain, the
   vertex has *headers* (nano/fee/shielded) → Python handles it;
5. compute the hash natively: `reverse(sha256(sha256(funds) ‖ sha256(graph) ‖ nonce))` via the
   `sha2` crate.

Output values use `decode_output_value` (`:117-136`), a faithful port of Python's strict
encoding (4-byte signed, or 8-byte negated with the top bit set), rejecting zero / out-of-range /
"fits-in-4-but-used-8" exactly like Python.

**Python side (`_vertex_parser.py:93-148`):** cheap pre-checks (length ≥ 2, valid `TxVersion`,
consensus version-validity) so Rust is only called for plausibly-valid versions; call
`htr_lib.parse_vertex(data, MAX_SERIALIZED_VERTEX_SIZE)`; if `None`, fall back; else unpack the
tuple, build `TxInput`/`TxOutput` lists, and construct the right subclass **passing the
Rust-computed hash through the constructor** (`hash=...`) — required because
`TokenCreationTransaction` derives its `tokens` from the hash (`:123-124`).

**GIL / copy:** `parse_vertex` takes `data: Vec<u8>`, so PyO3 **copies** the input bytes in and
holds the GIL throughout (parsing is microseconds — releasing the GIL isn't worth it here,
unlike the batch verify call which *does* release it). Internally the `Reader` borrows (no
per-field allocation), but values crossing the boundary (`tx_id`, `script`, `hash`, …) are
`.to_vec()`-copied. So: "copy in, borrow while scanning, copy out" — far fewer allocations than
Python, not end-to-end zero-copy.

**Errors:** there are **no exceptions** across this boundary. Every failure (unsupported version,
headers present, truncation, bad value, oversize, trailing bytes) is `None` → Python runs and is
authoritative for the actual rejection / error message.

## 3. The theory — why Rust is faster here

The Python parser pays CPython interpreter overhead on *every field*: each `struct.unpack`,
slice, and integer/object box is bytecode-dispatched and tends to allocate. For a tx with N
inputs and M outputs that's dozens–hundreds of interpreter round-trips and allocations per
vertex. Rust collapses this to inlined machine code (`u32::from_be_bytes`, a slice index), a
borrowing scanner that allocates nothing, `Vec::with_capacity(count)` for the collections (sizes
known from count bytes → no reallocation), **one** FFI crossing instead of many Python ops, and
the SHA-256 hash computed in the same native pass. Measured: parse **0.78 µs/tx**
(`plans/tps-bottlenecks-and-roadmap.md:60`).

## 4. Why it works / where it doesn't

**Correctness is a *differential round-trip property*, not independent re-derivation.** Whenever
Rust accepts, the reconstructed vertex must be byte-identical to Python's and the original bytes
must round-trip. `hathor_tests/tx/test_rust_vertex_parse.py` enforces this with a corpus (all
three kinds, edge values like max `2**63`, empty scripts, multi-input), every-truncation and
every-single-byte-flip mutations, and a Hypothesis fuzz pass — asserting type, hash,
`bytes(rust)==bytes(python)==data`, and each field. Because the parser only accepts **canonical**
encodings (anything it accepts re-serializes to itself), the same code can splice the sighash
preimage and stay byte-identical to Python's `get_sighash_all()`.

**Where Rust deliberately does NOT run (→ Python fallback):** vertices with headers (nano/fee/
shielded), other versions (merge-mined/PoA/on-chain-blueprint), oversize (Python raises the
proper `SerializedSizeError`), and any malformed bytes. **Python stays the single source of
truth for all rejection behaviour.** The differential suite therefore only needs to prove the
*acceptance* side.

**Risks to keep in mind:** the hash is computed by Rust and accepted by Python without
recomputation (passed via `hash=`), so correctness rests entirely on the differential tests; NaN
weight needs special compare handling in tests; `_origin_bytes` is hash-guarded so a later
mutate+rehash safely invalidates the cached bytes.

## 5. Gating — how to toggle S1 on/off

**Current state:** there is **no feature flag** — `deserialize()` unconditionally tries Rust
first (`_vertex_parser.py:65-70`). (The mode flag in this PR — `ScriptVerificationMode` — gates
S3S4 *verification*, not S1 parsing.)

**To gate it:** one branch does it — wrap the `self._deserialize_rust(...)` call at
`_vertex_parser.py:65-70` in the flag; when S1 is "baseline", go straight to
`_deserialize_python`. The Rust functions, the `Parsed` struct, and the tests simply go dormant.
Optionally gate the independent `_origin_bytes` assignment in `verify_bytes` for a clean A/B on
re-serialization avoidance.

**Key files:** `htr-rs/crates/htr-lib/src/vertex/mod.rs` (parser, hash, sighash, `parse_vertex`),
`htr-rs/crates/htr-lib/src/lib.rs:34-35` (FFI registration), `htr_lib.pyi:32-55` (FFI contract),
`hathor/transaction/vertex_parser/_vertex_parser.py:65-148` (dispatcher + glue + fallback),
`hathor/transaction/base_transaction.py:145,191,434-439` (`_origin_bytes`),
`hathor_tests/tx/test_rust_vertex_parse.py` (differential tests).
