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

import inspect
import time
from typing import TYPE_CHECKING

from hathorlib.conf.settings import HATHOR_TOKEN_UID
from hathorlib.nanocontracts.exception import BlueprintDoesNotExist
from hathorlib.token_info import TokenDescription, TokenVersion

if TYPE_CHECKING:
    from hathorlib.nanocontracts.blueprint import Blueprint
    from hathorlib.nanocontracts.types import BlueprintId


class SimulatorClock:
    """Clock that can be manually advanced for time-dependent tests.

    Implements ClockProtocol (seconds() -> float).
    """

    def __init__(self, initial_time: float | None = None) -> None:
        self._time = initial_time if initial_time is not None else time.time()

    def seconds(self) -> float:
        return self._time

    def advance(self, seconds: float) -> None:
        """Advance the clock by the given number of seconds."""
        self._time += seconds

    def set_time(self, timestamp: float) -> None:
        """Set the clock to a specific time."""
        self._time = timestamp


class InMemoryBlueprintService:
    """In-memory blueprint registry for the simulator.

    Implements BlueprintServiceProtocol.
    """

    def __init__(self) -> None:
        self._blueprints: dict[BlueprintId, type[Blueprint]] = {}

    def get_blueprint_class(self, blueprint_id: BlueprintId) -> type[Blueprint]:
        try:
            return self._blueprints[blueprint_id]
        except KeyError:
            raise BlueprintDoesNotExist(blueprint_id)

    def get_blueprint_source(self, blueprint_id: BlueprintId) -> str:
        bp = self.get_blueprint_class(blueprint_id)
        return inspect.getsource(bp)

    def register_blueprint(
        self, blueprint_id: bytes, blueprint: type[Blueprint], *, strict: bool = False
    ) -> None:
        from hathorlib.nanocontracts.types import BlueprintId as BId
        bid = BId(blueprint_id)
        if strict and bid in self._blueprints:
            raise ValueError(f'Blueprint {bid.hex()} already registered')
        self._blueprints[bid] = blueprint

    def register_blueprints(
        self, blueprints: dict[bytes, type[Blueprint]], *, strict: bool = False
    ) -> None:
        for bid, bp in blueprints.items():
            self.register_blueprint(bid, bp, strict=strict)


class InMemoryTxStorage:
    """In-memory token registry for the simulator.

    Implements NCTransactionStorageProtocol.
    """

    def __init__(
        self,
        hathor_token_name: str = 'Hathor',
        hathor_token_symbol: str = 'HTR',
    ) -> None:
        self._tokens: dict[bytes, TokenDescription] = {}
        # Register the native HTR token
        self._tokens[HATHOR_TOKEN_UID] = TokenDescription(
            token_id=HATHOR_TOKEN_UID,
            token_name=hathor_token_name,
            token_symbol=hathor_token_symbol,
            token_version=TokenVersion.NATIVE,
        )

    def get_token_description(self, token_uid: bytes) -> TokenDescription | None:
        return self._tokens.get(token_uid)

    def register_token(self, token: TokenDescription) -> None:
        """Register a custom token for testing."""
        self._tokens[token.token_id] = token
