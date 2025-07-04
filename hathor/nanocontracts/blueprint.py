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

from collections.abc import Callable
from functools import wraps
from typing import TYPE_CHECKING, Any, final

from hathor.nanocontracts.blueprint_env import BlueprintEnvironment
from hathor.nanocontracts.exception import BlueprintSyntaxError
from hathor.nanocontracts.fields.container import Container
from hathor.nanocontracts.nc_types.utils import pretty_type
from hathor.nanocontracts.types import (
    NC_ALLOWED_ACTIONS_ATTR,
    NC_FALLBACK_METHOD,
    NC_INITIALIZE_METHOD,
    NC_METHOD_TYPE_ATTR,
    NCMethodType,
)

if TYPE_CHECKING:
    from hathor.nanocontracts.nc_exec_logs import NCLogger

FORBIDDEN_NAMES = {
    'syscall',
    'log',
}

NC_FIELDS_ATTR: str = '__fields'


class _BlueprintBase(type):
    """Metaclass for blueprints.

    This metaclass will modify the attributes and set Fields to them according to their types.
    """

    def __new__(
        cls: type[_BlueprintBase],
        name: str,
        bases: tuple[type, ...],
        attrs: dict[str, Any],
        /,
        **kwargs: Any
    ) -> _BlueprintBase:
        from hathor.nanocontracts.fields import make_field_for_type

        # Initialize only subclasses of Blueprint.
        parents = [b for b in bases if isinstance(b, _BlueprintBase)]
        if not parents:
            return super().__new__(cls, name, bases, attrs, **kwargs)

        cls._validate_initialize_method(attrs)
        cls._validate_fallback_method(attrs)
        nc_fields = attrs.get('__annotations__', {})

        # Check for forbidden names.
        for field_name in nc_fields:
            if field_name in FORBIDDEN_NAMES:
                raise BlueprintSyntaxError(f'field name is forbidden: `{field_name}`')

            if field_name.startswith('_'):
                raise BlueprintSyntaxError(f'field name cannot start with underscore: `{field_name}`')

        # Create the fields attribute with the type for each field.
        attrs[NC_FIELDS_ATTR] = nc_fields

        # Use an empty __slots__ to prevent storing any attributes directly on instances.
        # The declared attributes are stored as fields on the class, so they still work despite the empty slots.
        attrs['__slots__'] = tuple()

        # Finally, create class!
        new_class = super().__new__(cls, name, bases, attrs, **kwargs)

        container_fields: list[str] = []

        # Create the Field instance according to each type.
        for field_name, field_type in attrs[NC_FIELDS_ATTR].items():
            value = getattr(new_class, field_name, None)
            if value is None:
                # This is the case when a type is specified but not a value.
                # Example:
                #     name: str
                #     age: int
                try:
                    field = make_field_for_type(field_name, field_type)
                except TypeError:
                    raise BlueprintSyntaxError(
                        f'unsupported field type: `{field_name}: {pretty_type(field_type)}`'
                    )
                setattr(new_class, field_name, field)
                if field.is_container:
                    container_fields.append(field_name)
            else:
                # This is the case when a value is specified.
                # Example:
                #     name: str = StrField()
                #
                # This was not implemented yet and will be extended later.
                raise BlueprintSyntaxError(f'fields with default values are currently not supported: `{field_name}`')

        # validation makes sure we already have it
        original_init_fn = getattr(new_class, NC_INITIALIZE_METHOD)
        init_containers_fn = _make_initialize_uninitialized_container_fields_fn(container_fields)

        # patch initialize method so it initializes containers fields implicitly
        @wraps(original_init_fn)
        def patched_init_fn(self: Blueprint, *args: Any, **kwargs: Any) -> Any:
            ret = original_init_fn(self, *args, **kwargs)
            init_containers_fn(self)
            return ret

        # copy important attributes
        important_attrs = [NC_METHOD_TYPE_ATTR, NC_ALLOWED_ACTIONS_ATTR, '__annotations__']
        for attr in important_attrs:
            setattr(patched_init_fn, attr, getattr(original_init_fn, attr))
        # XXX: this attribute is important for resolving the original method's signature
        setattr(patched_init_fn, '__wrapped__', original_init_fn)

        # replace the original init method
        setattr(new_class, NC_INITIALIZE_METHOD, patched_init_fn)

        return new_class

    @staticmethod
    def _validate_initialize_method(attrs: Any) -> None:
        if NC_INITIALIZE_METHOD not in attrs:
            raise BlueprintSyntaxError(f'blueprints require a method called `{NC_INITIALIZE_METHOD}`')

        method = attrs[NC_INITIALIZE_METHOD]
        method_type = getattr(method, NC_METHOD_TYPE_ATTR, None)

        if method_type is not NCMethodType.PUBLIC:
            raise BlueprintSyntaxError(f'`{NC_INITIALIZE_METHOD}` method must be annotated with @public')

    @staticmethod
    def _validate_fallback_method(attrs: Any) -> None:
        if NC_FALLBACK_METHOD not in attrs:
            return

        method = attrs[NC_FALLBACK_METHOD]
        method_type = getattr(method, NC_METHOD_TYPE_ATTR, None)

        if method_type is not NCMethodType.FALLBACK:
            raise BlueprintSyntaxError(f'`{NC_FALLBACK_METHOD}` method must be annotated with @fallback')


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


def _make_initialize_uninitialized_container_fields_fn(container_fields: list[str]) -> Callable[['Blueprint'], None]:
    def _initialize_uninitialized_container_fields(self: Blueprint) -> None:
        for field in container_fields:
            container: Container = getattr(self, field)
            assert isinstance(container, Container)
            container.__try_init_storage__()
    return _initialize_uninitialized_container_fields
