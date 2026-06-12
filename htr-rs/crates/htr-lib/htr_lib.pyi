from typing import Sequence


def sum_as_string(a: int, b: int) -> str:
    ...


def verify_vertex_stateless(
    checks: Sequence[int],
    data: object,
    num_workers: int,
) -> list[tuple[str, str] | None]:
    """Run the requested stateless checks for one vertex in a single GIL-released call (parallel
    on the shared rayon pool). One entry per requested check, in request order.

    `data` must expose the `StatelessVertexCheckData` fields as attributes (extracted by name).
    """
    ...


def count_sigops_inputs(
    pairs: Sequence[tuple[bytes, bytes]],
    max_multisig_pubkeys: int,
    enable_checkdatasig_count: bool,
    num_workers: int,
) -> list[tuple[tuple[str, str] | None, int]]:
    """Count sigops per (input_data, spent_output_script) pair (multisig redeem scripts are
    unwrapped). One (error, count) entry per pair, in order."""
    ...


def parse_vertex(
    data: bytes,
    max_size: int,
) -> tuple[
    int, int, float, int, int, bytes,           # version, signal_bits, weight, timestamp, nonce, hash
    list[bytes], list[bytes],                   # parents, tokens
    list[tuple[bytes, int, bytes]],             # inputs: (tx_id, index, data)
    list[tuple[int, bytes, int]],               # outputs: (value, script, token_data)
    bytes,                                      # block data
    tuple[int, str, str] | None,                # token info: (token_version, name, symbol)
] | None:
    """Parse a serialized vertex (regular block/tx/token-creation, no headers), returning the
    field tree plus the computed vertex hash — or None for anything unsupported or malformed
    (the caller falls back to the Python parser)."""
    ...


def sighash_from_vertex_bytes(
    data: bytes,
    max_size: int,
) -> bytes | None:
    """The sighash preimage of a serialized vertex (equals Python's `tx.get_sighash_all()`),
    or None when the bytes are unsupported (the caller computes it in Python)."""
    ...


def verify_scripts_from_bytes(
    items: Sequence[bytes],
    supplied_deps: Sequence[bytes],
    db: 'RocksDb | None',
    tx_cf: str,
    opcodes_version: int,
    max_size: int,
    max_multisig_pubkeys: int,
    max_multisig_signatures: int,
    p2pkh_version_byte: bytes,
    num_workers: int,
) -> list[tuple[int, list[tuple[str, str] | None], list[bytes]]]:
    """Fused batch script pipeline: parse each serialized tx, compute its sighash, resolve
    spent txs (batch -> supplied bytes -> native RocksDB read of `tx_cf`) and evaluate every
    input script — all in one GIL-released call. One `(status, results, missing)` per item:
    status 0 = evaluated (one result per input, in order), 1 = unresolvable deps (hashes
    listed), 2 = unsupported tx bytes."""
    ...


def verify_vertices_stateless_batch(
    items: Sequence[tuple[Sequence[int], object]],
    num_workers: int,
) -> list[list[tuple[str, str] | None]]:
    """Run the stateless checks for a batch of vertices in one GIL-released call, parallel
    across vertices. Each item is (checks, data) as in verify_vertex_stateless; result order
    matches the input."""
    ...


def verify_scripts_batch(
    jobs: Sequence[object],
    max_multisig_pubkeys: int,
    max_multisig_signatures: int,
    p2pkh_version_byte: bytes,
    num_workers: int,
) -> list[tuple[str, str] | None]:
    """Verify a batch of script jobs in parallel (GIL released), one result per job in order.

    Each job must expose the `ScriptVerificationJob` fields as attributes. A result of `None`
    means the script is valid; otherwise it is `(kind, message)` where `kind` is the Python
    exception class name the reference implementation would raise and `message` is debug-only.
    """
    ...


class RocksDbWriteBatch:
    """Atomic write batch for `RocksDb.write`. Single-use: consumed by `write`."""

    def __init__(self) -> None: ...
    def put(self, cf: str, key: bytes, value: bytes) -> None: ...
    def delete(self, cf: str, key: bytes) -> None: ...
    def len(self) -> int: ...


class RocksDbIterator:
    """Chunked column-family scan: one FFI call per chunk, not per item."""

    def next_chunk(self, n: int) -> list[tuple[bytes, bytes]]:
        """Return up to `n` (key, value) pairs; an empty list means exhausted (sticky)."""
        ...


class RocksDb:
    """Bytes-only handle over the primary RocksDB database (see plans/rust-rocksdb-storage.md).

    All methods release the GIL around the underlying RocksDB call. Column families are
    addressed by name; unknown names raise ValueError, I/O failures raise IOError, and any
    use after `close()` raises ValueError.
    """

    def __init__(self, path: str, cache_capacity: int | None = None) -> None: ...
    def get(self, cf: str, key: bytes) -> bytes | None: ...
    def multi_get(self, cf: str, keys: Sequence[bytes]) -> list[bytes | None]: ...
    def put(self, cf: str, key: bytes, value: bytes) -> None: ...
    def delete(self, cf: str, key: bytes) -> None: ...
    def write(self, batch: RocksDbWriteBatch) -> None: ...
    def iterator(
        self,
        cf: str,
        *,
        mode: str,
        key: bytes | None = None,
        reverse: bool = False,
    ) -> RocksDbIterator:
        """Open a chunked scan. `mode` is 'first', 'last', 'seek' or 'seek_for_prev' (the
        latter two require `key`); `reverse` sets the direction after the initial position."""
        ...
    def key_may_exist(self, cf: str, key: bytes) -> bool: ...
    def get_property(self, cf: str, name: str) -> str | None: ...
    def list_cfs(self) -> list[str]: ...
    def create_cf(self, name: str) -> None: ...
    def drop_cf(self, name: str) -> None: ...
    def flush(self) -> None: ...
    def close(self) -> None: ...
