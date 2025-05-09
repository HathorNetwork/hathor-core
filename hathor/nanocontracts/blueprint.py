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

from typing import TYPE_CHECKING, final

from hathor.nanocontracts.blueprint_env import BlueprintEnvironment
from hathor.nanocontracts.fields import get_field_for_attr

if TYPE_CHECKING:
    from hathor.nanocontracts.nc_exec_logs import NCLogger

FORBIDDEN_NAMES = {
    'syscall',
    'log',
}


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
        # Use an empty __slots__ to prevent storing any attributes directly on instances.
        # The declared attributes are stored as fields on the class, so they still work despite the empty slots.
        attrs['__slots__'] = tuple()
        # Finally, create class!
        new_class = super().__new__(cls, name, bases, attrs, **kwargs)

        # Check for forbidden names.
        # Note: This verification must be done AFTER calling super().__new__().
        for name in attrs.keys():
            if name in FORBIDDEN_NAMES:
                raise SyntaxError(f'Attempt to have a forbidden name: {name}')

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

    __slots__ = ('__env',)

    def __init__(self, env: BlueprintEnvironment) -> None:
        self.__env = env

    @final
    @property
    def syscall(self) -> BlueprintEnvironment:
        """Return the syscall provider for the current contract."""
        return self.__env

    @final
    @property
    def log(self) -> NCLogger:
        """Return the logger for the current contract."""
        return self.syscall.__log__
