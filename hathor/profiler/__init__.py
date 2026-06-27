# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from hathor.profiler.cpu import SimpleCPUProfiler

# Create a singleton to be used in the other modules.
# When using, call `get_cpu_profiler()` to get the singleton.
# You should NEVER access `_cpu_instance` directly.
_cpu_instance = SimpleCPUProfiler()


def get_cpu_profiler() -> SimpleCPUProfiler:
    """Return the singleton CPU profiler."""
    return _cpu_instance


__all__ = [
    'get_cpu_profiler',
]
