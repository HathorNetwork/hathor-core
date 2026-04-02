# Copyright 2026 Hathor Labs
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

from __future__ import annotations

from typing import TYPE_CHECKING

from hathorlib.conf.settings import FeatureSetting, HathorSettings
from hathorlib.nanocontracts.nano_runtime_version import NanoRuntimeVersion
from hathorlib.nanocontracts.runner.runner import RunnerFactory
from hathorlib.simulator.context_factory import ContextFactory
from hathorlib.simulator.id_generator import IdGenerator
from hathorlib.simulator.in_memory_services import InMemoryBlueprintService, InMemoryTxStorage, SimulatorClock
from hathorlib.simulator.in_memory_storage import InMemoryNCStorageFactory

if TYPE_CHECKING:
    from hathorlib.simulator.simulator import Simulator

# Default settings suitable for simulation (mainnet-like)
_SIMULATOR_SETTINGS = HathorSettings(
    NETWORK_NAME='mainnet',
    P2PKH_VERSION_BYTE=b'\x28',
    MULTISIG_VERSION_BYTE=b'\x64',
    ENABLE_NANO_CONTRACTS=FeatureSetting.ENABLED,
    ENABLE_NANO_RUNTIME_V2=FeatureSetting.ENABLED,
)


class SimulatorBuilder:
    """Configures and creates a Simulator instance.

    Example:
        sim = SimulatorBuilder().build()

        # Or with configuration:
        sim = (SimulatorBuilder()
            .with_seed(b'my_test_seed')
            .with_runtime_version(NanoRuntimeVersion.V2)
            .with_initial_time(1700000000.0)
            .with_auto_new_block(False)
            .build())
    """

    def __init__(self) -> None:
        self._seed: bytes = b'simulator_default_seed'
        self._runtime_version: NanoRuntimeVersion = NanoRuntimeVersion.V2
        self._initial_time: float | None = None
        self._settings: HathorSettings | None = None
        self._auto_new_block: bool = True
        self._unlimited_fuel: bool = False

    def with_seed(self, seed: bytes) -> SimulatorBuilder:
        """Set the RNG seed for deterministic execution."""
        self._seed = seed
        return self

    def with_runtime_version(self, version: NanoRuntimeVersion) -> SimulatorBuilder:
        """Set the nano runtime version."""
        self._runtime_version = version
        return self

    def with_initial_time(self, timestamp: float) -> SimulatorBuilder:
        """Set the initial clock time."""
        self._initial_time = timestamp
        return self

    def with_settings(self, settings: HathorSettings) -> SimulatorBuilder:
        """Provide custom HathorSettings."""
        self._settings = settings
        return self

    def with_auto_new_block(self, enabled: bool) -> SimulatorBuilder:
        """Set whether new_block() is called automatically after each successful call."""
        self._auto_new_block = enabled
        return self

    def with_unlimited_fuel(self) -> SimulatorBuilder:
        """Disable fuel metering for rapid prototyping."""
        self._unlimited_fuel = True
        return self

    def build(self) -> Simulator:
        """Build and return a configured Simulator instance."""
        from hathorlib.simulator.simulator import Simulator

        settings = self._settings or _SIMULATOR_SETTINGS

        if self._unlimited_fuel:
            settings = settings.model_copy(update=dict(
                NC_INITIAL_FUEL_TO_CALL_METHOD=2**63,
                NC_MEMORY_LIMIT_TO_CALL_METHOD=2**63,
            ))

        clock = SimulatorClock(initial_time=self._initial_time)
        storage_factory = InMemoryNCStorageFactory()
        blueprint_service = InMemoryBlueprintService()
        tx_storage = InMemoryTxStorage()
        id_generator = IdGenerator(seed=self._seed, address_version_byte=settings.P2PKH_VERSION_BYTE)
        context_factory = ContextFactory(clock=clock, id_generator=id_generator)

        runner_factory = RunnerFactory(
            reactor=clock,
            settings=settings,
            tx_storage=tx_storage,
            nc_storage_factory=storage_factory,
            blueprint_service=blueprint_service,
        )

        return Simulator(
            runner_factory=runner_factory,
            runtime_version=self._runtime_version,
            storage_factory=storage_factory,
            blueprint_service=blueprint_service,
            tx_storage=tx_storage,
            clock=clock,
            id_generator=id_generator,
            context_factory=context_factory,
            auto_new_block=self._auto_new_block,
        )
