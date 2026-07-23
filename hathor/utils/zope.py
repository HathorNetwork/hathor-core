# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from typing import Any, Optional, TypeVar, cast

from zope.interface import Interface
from zope.interface.exceptions import Invalid
from zope.interface.verify import verifyObject

T = TypeVar('T', bound=Interface)


def verified_cast(interface_class: type[T], obj: Any) -> Optional[T]:
    """
    Receive a zope interface and an object, and return a cast to this interface if the object implements it.
    Return None otherwise.
    """
    try:
        if verifyObject(interface_class, obj):
            return cast(T, obj)
    except Invalid:
        pass

    return None


def asserted_cast(interface_class: type[T], obj: Any) -> T:
    """
    Receive a zope interface and an object, and return a cast to this interface if the object implements it.
    Raise and AssertionError otherwise.
    """
    result = verified_cast(interface_class, obj)
    assert result is not None
    return result
