#  Copyright 2023 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

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
