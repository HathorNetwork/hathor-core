#  Copyright 2026 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from structlog import get_logger


if TYPE_CHECKING:
    from hathorlib.nanocontracts.types import BlueprintId
    from hathorlib.nanocontracts.blueprint import Blueprint

logger = get_logger()


class BlueprintServiceProtocol(Protocol):
    def get_blueprint_class(self, blueprint_id: BlueprintId) -> type[Blueprint]: ...
    def get_blueprint_source(self, blueprint_id: BlueprintId) -> str: ...
    def register_blueprint(self, blueprint_id: bytes, blueprint: type[Blueprint], *, strict: bool = False) -> None: ...
    def register_blueprints(self, blueprints: dict[bytes, type[Blueprint]], *, strict: bool = False) -> None: ...
