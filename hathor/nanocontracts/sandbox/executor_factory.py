# Copyright 2024 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Factory for creating MeteredExecutor instances with context-appropriate configs.

This module provides a factory pattern that centralizes all "which config for which context"
logic, eliminating the need to pass sandbox_config through the call chain.

The factory pattern encapsulates config selection and provides context-appropriate executors:
- for_loading(): Executor for blueprint loading (lower op limit)
- for_execution(): Executor for consensus execution (standard limits)
- for_api(): Executor for API views (higher limits, runtime-reloadable)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from hathor.nanocontracts.sandbox.config import DISABLED_CONFIG, SandboxConfig

if TYPE_CHECKING:
    from hathor.nanocontracts.metered_exec import MeteredExecutor
    from hathor.nanocontracts.sandbox.config_loader import SandboxAPIConfigLoader


class MeteredExecutorFactory:
    """Factory for creating context-appropriate MeteredExecutor instances.

    This centralizes all sandbox config selection logic, eliminating the need to
    pass sandbox_config through multiple layers of the codebase.

    All config parameters default to DISABLED_CONFIG, so constructing with no
    arguments gives a fully-disabled factory (replacing the old
    DisabledMeteredExecutorFactory). Passing specific configs replaces both
    the old ProductionMeteredExecutorFactory and TestMeteredExecutorFactory.
    """

    __slots__ = ('_loading_config', '_execution_config', '_api_loader')

    def __init__(
        self,
        *,
        loading_config: SandboxConfig = DISABLED_CONFIG,
        execution_config: SandboxConfig = DISABLED_CONFIG,
        api_config_loader: 'SandboxAPIConfigLoader | None' = None,
    ) -> None:
        self._loading_config = loading_config
        self._execution_config = execution_config
        self._api_loader = api_config_loader

    def for_loading(self) -> MeteredExecutor:
        """Create executor for blueprint loading.

        Blueprint loading uses lower operation limits (e.g., 100K ops) to prevent
        DoS attacks during the loading phase.
        """
        from hathor.nanocontracts.metered_exec import MeteredExecutor
        return MeteredExecutor(config=self._loading_config)

    def for_execution(self) -> MeteredExecutor:
        """Create executor for consensus execution.

        Consensus execution uses standard operation limits (e.g., 1M ops).
        This config is consensus-critical and must be deterministic.
        """
        from hathor.nanocontracts.metered_exec import MeteredExecutor
        return MeteredExecutor(config=self._execution_config)

    def for_api(self) -> MeteredExecutor:
        """Create executor for API view methods.

        API views use higher limits (e.g., 10M ops) and can be configured
        at runtime via external config files. This is local to each node
        and not consensus-critical.

        Requires an api_config_loader to be set.
        """
        from hathor.nanocontracts.metered_exec import MeteredExecutor
        assert self._api_loader is not None, "api_config_loader must be set to create API executors"
        return MeteredExecutor(config=self._api_loader.config)
