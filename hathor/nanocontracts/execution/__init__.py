#  Copyright 2025 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

"""Nano contract block execution module."""

from hathor.nanocontracts.execution.block_executor import NCBlockExecutor
from hathor.nanocontracts.execution.consensus_block_executor import NCConsensusBlockExecutor

# Subprocess-related imports are done lazily to avoid circular imports
# Users should import directly from the submodules when needed:
#   from hathor.nanocontracts.execution.subprocess_block_executor import NCSubprocessBlockExecutor
#   from hathor.nanocontracts.execution.subprocess_pool import NCSubprocessPool

__all__ = [
    'NCBlockExecutor',
    'NCConsensusBlockExecutor',
]
