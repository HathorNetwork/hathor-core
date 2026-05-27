#  Copyright 2023 Hathor Labs
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

import hashlib
import importlib.util
import os
from types import ModuleType
from typing import TYPE_CHECKING, Callable, Optional

if TYPE_CHECKING:
    from hathor.dag_builder.artifacts import DAGArtifacts
    from hathor.manager import HathorManager
    from hathor.simulator import Simulator

_DEFAULT_REWARD_SPEND_MIN_BLOCKS = 10


class ExternalScenario:
    """Loads an external Python scenario file and exposes the same interface as the Scenario enum."""

    def __init__(self, file_path: str, function_name: str = 'simulate') -> None:
        module = self._load_module(file_path)

        if not hasattr(module, function_name):
            raise ValueError(f"Function '{function_name}' not found in {file_path}")
        self._fn: Callable = getattr(module, function_name)

        self._reward_spend_min_blocks = _DEFAULT_REWARD_SPEND_MIN_BLOCKS
        if hasattr(module, 'REWARD_SPEND_MIN_BLOCKS'):
            value = module.REWARD_SPEND_MIN_BLOCKS
            if not isinstance(value, int):
                raise ValueError(
                    f'REWARD_SPEND_MIN_BLOCKS must be an int, got {type(value).__name__}'
                )
            self._reward_spend_min_blocks = value

    def _load_module(self, file_path: str) -> ModuleType:
        if not os.path.isfile(file_path):
            raise ValueError(f'External scenario file not found: {file_path}')
        module_name = '_hathor_external_' + hashlib.md5(file_path.encode()).hexdigest()[:8]
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        if spec is None:
            raise ValueError(f'Could not load module spec from: {file_path}')
        if spec.loader is None:
            raise ValueError(f'No loader available for: {file_path}')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # type: ignore[union-attr]
        return module

    def simulate(self, simulator: 'Simulator', manager: 'HathorManager') -> 'Optional[DAGArtifacts]':
        return self._fn(simulator, manager)

    def get_reward_spend_min_blocks(self) -> int:
        return self._reward_spend_min_blocks
