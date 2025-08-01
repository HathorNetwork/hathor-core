#  Copyright 2025 Hathor Labs
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

import pytest

from hathor.nanocontracts.faux_immutability import _FauxImmutabilityMeta


def test_success() -> None:
    class C(metaclass=_FauxImmutabilityMeta):
        __slots__ = ()


def test_missing_slots() -> None:
    with pytest.raises(TypeError, match='faux-immutable class `C` must define `__slots__`'):
        class C(metaclass=_FauxImmutabilityMeta):
            pass


def test_override_setattr() -> None:
    with pytest.raises(TypeError, match='faux-immutable class `C` must not define `__setattr__`'):
        class C(metaclass=_FauxImmutabilityMeta):
            __slots__ = ()

            def __setattr__(self, name: str, value: object) -> None:
                pass


def test_override_delattr() -> None:
    with pytest.raises(TypeError, match='faux-immutable class `C` must not define `__delattr__`'):
        class C(metaclass=_FauxImmutabilityMeta):
            __slots__ = ()

            def __delattr__(self, name: str) -> None:
                pass


def test_immutable_superclass_success() -> None:
    class Super(metaclass=_FauxImmutabilityMeta):
        __slots__ = ()

    class C(Super, metaclass=_FauxImmutabilityMeta):
        __slots__ = ()


def test_mutable_superclass() -> None:
    class Super:
        pass

    with pytest.raises(TypeError, match='faux-immutable class `C` cannot have non-faux-immutable base class `Super`'):
        class C(Super, metaclass=_FauxImmutabilityMeta):
            __slots__ = ()
