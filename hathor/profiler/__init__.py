# Copyright 2021 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
