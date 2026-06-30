"""Dependency-free process resource readers (Linux /proc).

We read /proc/self directly rather than depend on psutil: zero new deps, and these are
exactly the fields we need. Bytes are returned as ints (a count of bytes)."""
from __future__ import annotations

import os


def read_rss_bytes() -> int:
    """Resident set size — physical RAM held by this process, in bytes."""
    with open("/proc/self/status", encoding="ascii") as fh:
        for line in fh:
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024  # value is in kB
    return 0


def read_vmhwm_bytes() -> int:
    """Peak RSS ever reached by this process (high-water mark), in bytes."""
    with open("/proc/self/status", encoding="ascii") as fh:
        for line in fh:
            if line.startswith("VmHWM:"):
                return int(line.split()[1]) * 1024
    return 0


def read_fd_count() -> int:
    """Number of open file descriptors."""
    try:
        return len(os.listdir("/proc/self/fd"))
    except OSError:
        return 0


def read_io() -> tuple[int, int]:
    """(read_bytes, write_bytes) — actual block-device I/O since process start.

    These are the disk-level counters (not rchar/wchar, which include page cache)."""
    read_bytes = write_bytes = 0
    try:
        with open("/proc/self/io", encoding="ascii") as fh:
            for line in fh:
                if line.startswith("read_bytes:"):
                    read_bytes = int(line.split()[1])
                elif line.startswith("write_bytes:"):
                    write_bytes = int(line.split()[1])
    except OSError:
        pass
    return read_bytes, write_bytes
