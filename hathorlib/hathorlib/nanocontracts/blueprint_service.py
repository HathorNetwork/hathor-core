# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from structlog import get_logger

if TYPE_CHECKING:
    from hathorlib.nanocontracts.blueprint import Blueprint
    from hathorlib.nanocontracts.types import BlueprintId

logger = get_logger()


class BlueprintServiceProtocol(Protocol):
    def get_blueprint_class(self, blueprint_id: BlueprintId) -> type[Blueprint]: ...
    def get_blueprint_source(self, blueprint_id: BlueprintId) -> str: ...
    def register_blueprint(self, blueprint_id: bytes, blueprint: type[Blueprint], *, strict: bool = False) -> None: ...
    def register_blueprints(self, blueprints: dict[bytes, type[Blueprint]], *, strict: bool = False) -> None: ...
