# Copyright 2023 Hathor Labs
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

from hathor.nanocontracts.types import BlueprintId

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings
    from hathor.nanocontracts.blueprint import Blueprint


_BLUEPRINTS_MAPPER: dict[str, type[Blueprint]] = {}


class NCBlueprintCatalog:
    """Catalog of blueprints available."""
    __slots__ = ('_blueprints',)

    def __init__(self) -> None:
        self._blueprints: dict[bytes, type[Blueprint]] = {}

    def get_blueprint_class(self, blueprint_id: BlueprintId) -> type[Blueprint] | None:
        """Return the blueprint class related to the given blueprint id or None if it doesn't exist."""
        return self._blueprints.get(blueprint_id)

    def register_blueprints(self, blueprints: dict[bytes, type[Blueprint]], *, strict: bool = False) -> None:
        """Register blueprints in the catalog."""
        if strict:
            for blueprint_id in blueprints:
                if blueprint := self._blueprints.get(blueprint_id):
                    raise ValueError(f'Blueprint {blueprint_id.hex()} is already registered: {blueprint.__name__}')
        self._blueprints.update(blueprints)

    def get_all(self) -> dict[bytes, type[Blueprint]]:
        """Return a copy of all registered blueprints."""
        return dict(self._blueprints)

    @staticmethod
    def generate_blueprints_from_settings(settings: HathorSettings) -> dict[bytes, type[Blueprint]]:
        """Generate a map of blueprints based on the provided settings."""
        assert settings.ENABLE_NANO_CONTRACTS
        blueprints: dict[bytes, type[Blueprint]] = {}
        for id_, name in settings.BLUEPRINTS.items():
            blueprints[id_] = _BLUEPRINTS_MAPPER[name]
        return blueprints
