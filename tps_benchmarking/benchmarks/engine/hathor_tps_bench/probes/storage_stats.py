"""Storage-side probes: force deferred RocksDB writes, read storage size.

RocksDB writes are deferred to a background flush, so per-stage S5 disk I/O is not
faithful; we `flush()` at the batch boundary and read the authoritative disk figure
from /proc afterwards (RFC §"Measuring memory, disk I/O, and file descriptors")."""
from __future__ import annotations

from typing import Any


def flush(manager: Any) -> None:
    """Realise any deferred RocksDB writes (best-effort)."""
    fn = getattr(manager.tx_storage, "flush", None)
    if callable(fn):
        try:
            fn()
        except Exception:  # noqa: BLE001 — flushing must never break a run
            pass


def read_sst_bytes(manager: Any) -> int:
    """Total RocksDB SST-file size, if cheaply available; else 0.

    Not wired in CP-4 — the authoritative disk signal is the /proc write_bytes delta.
    Left as a hook for a later RocksDB-stats probe."""
    return 0
