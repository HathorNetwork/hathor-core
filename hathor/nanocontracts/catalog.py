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

from typing import TYPE_CHECKING, Type

from hathor.nanocontracts.blueprints import _blueprints_mapper
from hathor.nanocontracts.exception import BlueprintDoesNotExist

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings
    from hathor.nanocontracts.blueprint import Blueprint


class NCBlueprintCatalog:
    """Catalog of blueprints available."""

    def __init__(self, blueprints: dict[bytes, Type['Blueprint']]) -> None:
        self.blueprints = blueprints

    def get_blueprint_class(self, blueprint_id: bytes) -> Type['Blueprint']:
        """Return the blueprint class related to the given blueprint id."""
        blueprint_class = self.blueprints.get(blueprint_id, None)
        if blueprint_class is None:
            raise BlueprintDoesNotExist(blueprint_id.hex())
        return blueprint_class


def generate_catalog_from_settings(settings: 'HathorSettings') -> NCBlueprintCatalog:
    """Generate a catalog of blueprints based on the provided settings."""
    assert settings.ENABLE_NANO_CONTRACTS
    blueprints: dict[bytes, Type['Blueprint']] = {}
    for _id, _name in settings.BLUEPRINTS.items():
        blueprints[_id] = _blueprints_mapper[_name]
    return NCBlueprintCatalog(blueprints)
