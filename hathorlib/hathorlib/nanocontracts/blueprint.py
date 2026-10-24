# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import sys
from typing import TYPE_CHECKING, Any, cast, final

from hathorlib.nanocontracts.blueprint_env import BlueprintEnvironment
from hathorlib.nanocontracts.exception import BlueprintSyntaxError
from hathorlib.nanocontracts.nc_types.utils import pretty_type
from hathorlib.nanocontracts.types import NC_FALLBACK_METHOD, NC_INITIALIZE_METHOD, NC_METHOD_TYPE_ATTR, NCMethodType

if TYPE_CHECKING:
    from hathorlib.nanocontracts.nc_exec_logs import NCLogger

if sys.version_info >= (3, 14):
    import annotationlib
else:
    annotationlib = None

FORBIDDEN_NAMES = {
    'syscall',
    'log',
}

NC_FIELDS_ATTR: str = '__fields'


def _get_class_annotations(attrs: dict[str, Any]) -> dict[str, Any]:
    annotations = attrs.get('__annotations__')
    if annotations is not None:
        return cast(dict[str, Any], annotations)

    if annotationlib is None:
        return {}

    annotate = annotationlib.get_annotate_from_class_namespace(attrs)
    if annotate is None:
        return {}

    return annotationlib.call_annotate_function(annotate, annotationlib.Format.VALUE)


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
        from hathorlib.nanocontracts.fields import make_field_for_type

        # Initialize only subclasses of Blueprint.
        parents = [b for b in bases if isinstance(b, _BlueprintBase)]
        if not parents:
            return super().__new__(cls, name, bases, attrs, **kwargs)

        cls._validate_initialize_method(attrs)
        cls._validate_fallback_method(attrs)
        nc_fields = _get_class_annotations(attrs)

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
            else:
                # This is the case when a value is specified.
                # Example:
                #     name: str = StrField()
                #
                # This was not implemented yet and will be extended later.
                raise BlueprintSyntaxError(f'fields with default values are currently not supported: `{field_name}`')

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
