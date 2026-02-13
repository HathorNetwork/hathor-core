# Copyright 2021 Hathor Labs
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
from typing import Any, Union

from pydantic import ConfigDict, field_validator, model_validator
from typing_extensions import Self

from hathor.checkpoint import Checkpoint
from hathor.consensus.consensus_settings import ConsensusSettings, PowSettings
from hathor.feature_activation.settings import Settings as FeatureActivationSettings
from hathorlib.conf.settings import HathorSettings as LibSettings

from hathor.nanocontracts.sandbox import DISABLED_CONFIG, SandboxConfig

DECIMAL_PLACES = 2

GENESIS_TOKEN_UNITS = 1 * (10 ** 9)  # 1B
GENESIS_TOKENS = GENESIS_TOKEN_UNITS * (10 ** DECIMAL_PLACES)  # 100B

HATHOR_TOKEN_UID: bytes = b'\x00'


class HathorSettings(LibSettings):
    model_config = ConfigDict(extra='forbid')

    # Block checkpoints
    CHECKPOINTS: list[Checkpoint] = []

    @field_validator('CHECKPOINTS', mode='before')
    @classmethod
    def _parse_checkpoints(cls, checkpoints: Union[dict[int, str], list[Checkpoint]]) -> list[Checkpoint]:
        """Parse a dictionary of raw checkpoint data into a list of checkpoints."""
        if isinstance(checkpoints, dict):
            return [
                Checkpoint(height, bytes.fromhex(_hash))
                for height, _hash in checkpoints.items()
            ]

        if not isinstance(checkpoints, list):
            raise TypeError(f'expected \'dict[int, str]\' or \'list[Checkpoint]\', got {checkpoints}')

        return checkpoints

    # All settings related to Feature Activation
    FEATURE_ACTIVATION: FeatureActivationSettings = FeatureActivationSettings()

    @field_validator('FEATURE_ACTIVATION', mode='before')
    @classmethod
    def parse_feature_activation(cls, v: dict[str, Any]) -> FeatureActivationSettings:
        if isinstance(v, dict):
            return FeatureActivationSettings.model_validate(v)
        else:
            return v

    # The consensus algorithm protocol settings.
    CONSENSUS_ALGORITHM: ConsensusSettings = PowSettings()

    @model_validator(mode='after')
    def _validate_consensus_algorithm(self) -> Self:
        """Validate that if Proof-of-Authority is enabled, block rewards must not be set."""
        consensus_algorithm = self.CONSENSUS_ALGORITHM
        if consensus_algorithm.is_pow():
            return self

        if (self.BLOCKS_PER_HALVING is not None or
            self.INITIAL_TOKEN_UNITS_PER_BLOCK != 0 or
                self.MINIMUM_TOKEN_UNITS_PER_BLOCK != 0):
            raise ValueError('PoA networks do not support block rewards')
        return self

    # Sandbox configuration for blueprint loading (consensus-critical).
    # Use DISABLED_CONFIG to disable sandbox protection during blueprint loading.
    # Use DEFAULT_CONFIG_LOADING (or a custom SandboxConfig) to enable it.
    NC_SANDBOX_CONFIG_LOADING: SandboxConfig = DISABLED_CONFIG

    @field_validator('NC_SANDBOX_CONFIG_LOADING', mode='before')
    @classmethod
    def _parse_sandbox_config_loading(cls, value: Union[str, SandboxConfig, None]) -> SandboxConfig:
        """Parse sandbox config for loading from YAML."""
        return _resolve_sandbox_config(value)

    # Sandbox configuration for method execution (consensus-critical).
    # Use DISABLED_CONFIG to disable sandbox protection during method execution.
    # Use DEFAULT_CONFIG_EXECUTION (or a custom SandboxConfig) to enable it.
    NC_SANDBOX_CONFIG_EXECUTION: SandboxConfig = DISABLED_CONFIG

    @field_validator('NC_SANDBOX_CONFIG_EXECUTION', mode='before')
    @classmethod
    def _parse_sandbox_config_execution(cls, value: Union[str, SandboxConfig, None]) -> SandboxConfig:
        """Parse sandbox config for execution from YAML."""
        return _resolve_sandbox_config(value)

    # Sandbox configuration for API view method calls (local, not consensus-critical).
    # Use None or DISABLED_CONFIG to disable sandbox protection during API calls.
    # Use DEFAULT_CONFIG_API (or a custom SandboxConfig) to enable it.
    # Runtime config file override can be specified via CLI --nc-sandbox-api-config-file argument.
    NC_SANDBOX_CONFIG_API: SandboxConfig | None = None

    @field_validator('NC_SANDBOX_CONFIG_API', mode='before')
    @classmethod
    def _parse_sandbox_config_api(cls, value: Union[str, SandboxConfig, None]) -> SandboxConfig | None:
        """Parse sandbox config for API views from YAML."""
        return _resolve_sandbox_config_optional(value)


def _resolve_sandbox_config(value: Union[str, SandboxConfig, None]) -> SandboxConfig:
    """Resolve a sandbox config from a YAML value.

    Accepts:
        - None: returns DISABLED_CONFIG
        - SandboxConfig instance: returned as-is
        - str: a fully-qualified Python dotted path to a SandboxConfig constant
          (e.g., 'hathor.nanocontracts.sandbox.config.DEFAULT_CONFIG_LOADING')
    """
    if value is None:
        return DISABLED_CONFIG
    if isinstance(value, SandboxConfig):
        return value
    if isinstance(value, str):
        return _import_sandbox_config(value)
    raise TypeError(
        f"sandbox config must be a dotted path string, SandboxConfig, or null, got: {type(value).__name__}"
    )


def _resolve_sandbox_config_optional(value: Union[str, SandboxConfig, None]) -> SandboxConfig | None:
    """Like _resolve_sandbox_config but allows None to pass through."""
    if value is None:
        return None
    return _resolve_sandbox_config(value)


def _import_sandbox_config(dotted_path: str) -> SandboxConfig:
    """Import a SandboxConfig from a fully-qualified Python dotted path.

    Example: 'hathor.nanocontracts.sandbox.config.DEFAULT_CONFIG_LOADING'
    """
    import importlib

    if '.' not in dotted_path:
        raise ValueError(
            f"sandbox config must be a fully-qualified dotted path "
            f"(e.g., 'hathor.nanocontracts.sandbox.config.DEFAULT_CONFIG_LOADING'), got: {dotted_path!r}"
        )
    module_path, _, attr_name = dotted_path.rpartition('.')
    try:
        module = importlib.import_module(module_path)
    except ImportError as e:
        raise ValueError(f"cannot import module {module_path!r}: {e}") from e
    try:
        config = getattr(module, attr_name)
    except AttributeError as e:
        raise ValueError(f"module {module_path!r} has no attribute {attr_name!r}") from e
    if not isinstance(config, SandboxConfig):
        raise TypeError(
            f"{dotted_path!r} resolved to {type(config).__name__}, expected SandboxConfig"
        )
    return config
