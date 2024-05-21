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

from typing import Any

from structlog import get_logger

from hathor.conf import HathorSettings
from hathor.nanocontracts.fields import get_field_for_attr
from hathor.nanocontracts.storage import NCBaseStorage

logger = get_logger()
settings = HathorSettings()


class _BlueprintBase(type):
    """Metaclass for blueprints.

    This metaclass will modify the attributes and set Fields to them according to their types.
    """

    def __new__(cls, name, bases, attrs, **kwargs):
        # Initialize only subclasses of Blueprint.
        parents = [b for b in bases if isinstance(b, _BlueprintBase)]
        if not parents:
            return super().__new__(cls, name, bases, attrs, **kwargs)

        # Create the `_fields` attribute with the type for each field.
        attrs['_fields'] = attrs.get('__annotations__', {})
        new_class = super().__new__(cls, name, bases, attrs, **kwargs)

        # Create the Field instance according to each type.
        for name, _type in attrs['_fields'].items():
            if name.startswith('_'):
                raise SyntaxError('cannot start with _')
            value = getattr(new_class, name, None)
            if value is None:
                # This is the case when a type is specified but not a value.
                # Example:
                #     name: str
                #     age: int
                field = get_field_for_attr(name, _type)
                setattr(new_class, name, field)
            else:
                # This is the case when a value is specified.
                # Example:
                #     name: str = StrField()
                #
                # This was not implemented yet and will be extended later.
                raise NotImplementedError

        return new_class


class Blueprint(metaclass=_BlueprintBase):
    """Base class for all blueprints.

    Example:

        class MyBlueprint(Blueprint):
            name: str
            age: int
    """

    def __init__(self, storage: NCBaseStorage):
        self.log = logger.new()
        self._storage = storage
        self._cache: dict[str, Any] = {}
