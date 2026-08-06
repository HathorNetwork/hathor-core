"""Physical CPU topology, without psutil.

The verification pool's optimum tracks **physical** cores, not logical ones: measured on the
reference i5-11300H (4 physical / 8 logical), throughput peaked at 4 workers and collapsed at 8,
because 8 rayon workers claim every logical thread and preempt the single-threaded driver and
RocksDB's compaction threads. So the pool must be sized from physical cores.

Python has no stdlib physical-core count (`os.cpu_count()` is logical), and this package avoids
psutil on purpose — `procstats.py` reads /proc directly for the same reason. Hence this module.

Every probe is best-effort and falls back rather than raising: an unknown topology degrades to the
logical count, which is a worse pool size but never a broken run.
"""
from __future__ import annotations

import os
import platform
import subprocess


def _linux_physical() -> int | None:
    """Count distinct (physical id, core id) pairs in /proc/cpuinfo.

    Absent on many ARM kernels, which simply omit those keys — hence the None."""
    try:
        with open("/proc/cpuinfo", encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        return None
    pairs, pkg, core = set(), None, None
    for line in text.splitlines():
        if ":" not in line:
            if pkg is not None and core is not None:   # blank line ends a processor block
                pairs.add((pkg, core))
            pkg = core = None
            continue
        key, _, val = line.partition(":")
        key, val = key.strip(), val.strip()
        if key == "physical id":
            pkg = val
        elif key == "core id":
            core = val
    if pkg is not None and core is not None:
        pairs.add((pkg, core))
    return len(pairs) or None


def _sysctl_physical() -> int | None:
    """macOS: hw.physicalcpu."""
    try:
        out = subprocess.run(["sysctl", "-n", "hw.physicalcpu"], capture_output=True,
                             text=True, timeout=5, check=True).stdout.strip()
        return int(out) or None
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def _windows_physical() -> int | None:
    """Windows: PowerShell CIM query. `wmic` is removed on recent builds, so it is not used."""
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "(Get-CimInstance Win32_Processor | Measure-Object -Property NumberOfCores "
             "-Sum).Sum"],
            capture_output=True, text=True, timeout=15, check=True).stdout.strip()
        return int(out) or None
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def physical_cores() -> int | None:
    """Physical core count, or None when the platform will not say."""
    system = platform.system()
    probe = {"Linux": _linux_physical, "Darwin": _sysctl_physical,
             "Windows": _windows_physical}.get(system)
    return probe() if probe else None


def logical_cores() -> int:
    return os.cpu_count() or 1


def default_script_workers() -> int:
    """Pool size to use when the caller did not choose one.

    Physical cores when known; otherwise the logical count, which oversubscribes on an SMT machine
    but still runs. Never returns 0 — that value means "no pool at all" to the harness."""
    return max(1, physical_cores() or logical_cores())


def describe() -> dict:
    """Machine context to record alongside a run.

    Throughput here is a single-thread, hardware-specific figure, so a result without its machine
    is not comparable to any other result. Recording this is what makes cross-machine comparison
    (and, later, a fleet dashboard) meaningful rather than misleading."""
    return {
        "cpu_model": _cpu_model(),
        "physical_cores": physical_cores(),
        "logical_cores": logical_cores(),
        "platform": platform.platform(),
        "python": platform.python_version(),
    }


def _cpu_model() -> str | None:
    if platform.system() == "Linux":
        try:
            with open("/proc/cpuinfo", encoding="utf-8") as fh:
                for line in fh:
                    if line.startswith("model name"):
                        return line.partition(":")[2].strip()
        except OSError:
            pass
    return platform.processor() or None
