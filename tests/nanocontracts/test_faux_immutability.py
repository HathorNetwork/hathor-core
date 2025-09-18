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

from hathor.nanocontracts.faux_immutable import FauxImmutable, create_with_shell


def test_missing_slots() -> None:
    with pytest.raises(TypeError, match='faux-immutable class `Foo` must define `__slots__`'):
        class Foo(FauxImmutable):
            pass


def test_defines_dunder() -> None:
    with pytest.raises(TypeError, match='faux-immutable class `Foo1` must not define `__setattr__`'):
        class Foo1(FauxImmutable):
            __slots__ = ()

            def __setattr__(self, name: str, value: object) -> None:
                pass

    with pytest.raises(TypeError, match='faux-immutable class `Foo2` must not define `__setattr__`'):
        class Foo2(FauxImmutable):
            __slots__ = ()

            def __setattr__(self, name: str, value: object) -> None:
                pass


def test_invalid_inheritance() -> None:
    class Super:
        pass

    with pytest.raises(TypeError, match='faux-immutable only allows one base'):
        class Foo(FauxImmutable, Super):
            __slots__ = ()


def test_immutability_success() -> None:
    class Foo(FauxImmutable):
        __slots__ = ('attr',)
        class_attr = 'foo'

        def method(self) -> None:
            pass

        @classmethod
        def class_method(cls) -> None:
            pass

    foo = Foo()

    #
    # Existing attribute on instance
    #

    # protected by FauxImmutable.__setattr__
    with pytest.raises(AttributeError, match='cannot set attribute `attr` on faux-immutable object'):
        foo.attr = 123

    # protected by FauxImmutable.__setattr__
    with pytest.raises(AttributeError, match='cannot set attribute `attr` on faux-immutable object'):
        setattr(foo, 'attr', 123)

    # it doesn't protect against this case
    object.__setattr__(foo, 'attr', 123)

    #
    # Existing class attribute on instance
    #

    # protected by FauxImmutable.__setattr__
    with pytest.raises(AttributeError, match='cannot set attribute `class_attr` on faux-immutable object'):
        foo.class_attr = 'bar'

    # protected by FauxImmutable.__setattr__
    with pytest.raises(AttributeError, match='cannot set attribute `class_attr` on faux-immutable object'):
        setattr(foo, 'class_attr', 123)

    # protected by FauxImmutable.__slots__
    with pytest.raises(AttributeError, match="'Foo' object attribute 'class_attr' is read-only"):
        object.__setattr__(foo, 'class_attr', 123)

    #
    # Existing method on instance
    #

    # protected by FauxImmutable.__setattr__
    with pytest.raises(AttributeError, match='cannot set attribute `method` on faux-immutable object'):
        foo.method = lambda: None  # type: ignore[method-assign]

    # protected by FauxImmutable.__setattr__
    with pytest.raises(AttributeError, match='cannot set attribute `method` on faux-immutable object'):
        setattr(foo, 'method', lambda: None)

    # protected by Foo.__slots__
    with pytest.raises(AttributeError, match="'Foo' object attribute 'method' is read-only"):
        object.__setattr__(foo, 'method', lambda: None)

    #
    # Existing class method on instance
    #

    # protected by FauxImmutable.__setattr__
    with pytest.raises(AttributeError, match='cannot set attribute `class_method` on faux-immutable object'):
        foo.class_method = lambda: None  # type: ignore[method-assign]

    # protected by FauxImmutable.__setattr__
    with pytest.raises(AttributeError, match='cannot set attribute `class_method` on faux-immutable object'):
        setattr(foo, 'class_method', lambda: None)

    # protected by FauxImmutable.__slots__
    with pytest.raises(AttributeError, match="'Foo' object attribute 'class_method' is read-only"):
        object.__setattr__(foo, 'class_method', lambda: None)

    #
    # New attribute on instance
    #

    # protected by FauxImmutable.__setattr__
    with pytest.raises(AttributeError, match='cannot set attribute `new_attr` on faux-immutable object'):
        foo.new_attr = 123

    # protected by FauxImmutable.__setattr__
    with pytest.raises(AttributeError, match='cannot set attribute `new_attr` on faux-immutable object'):
        setattr(foo, 'new_attr', 123)

    # protected by Foo.__slots__
    with pytest.raises(AttributeError, match="'Foo' object has no attribute 'new_attr'"):
        object.__setattr__(foo, 'new_attr', 123)

    #
    # Existing attribute on class
    #

    # protected by FauxImmutableMeta.__setattr__
    with pytest.raises(AttributeError, match='cannot set attribute `attr` on faux-immutable class'):
        Foo.attr = 'bar'

    # protected by FauxImmutableMeta.__setattr__
    with pytest.raises(AttributeError, match='cannot set attribute `attr` on faux-immutable class'):
        setattr(Foo, 'attr', 'bar')

    # protected by Python itself
    with pytest.raises(TypeError, match="can't apply this __setattr__ to FauxImmutableMeta object"):
        object.__setattr__(Foo, 'attr', 'bar')

    #
    # Existing class attribute on class
    #

    # protected by FauxImmutableMeta.__setattr__
    with pytest.raises(AttributeError, match='cannot set attribute `class_attr` on faux-immutable class'):
        Foo.class_attr = 'bar'

    # protected by FauxImmutableMeta.__setattr__
    with pytest.raises(AttributeError, match='cannot set attribute `class_attr` on faux-immutable class'):
        setattr(Foo, 'class_attr', 'bar')

    # protected by Python itself
    with pytest.raises(TypeError, match="can't apply this __setattr__ to FauxImmutableMeta object"):
        object.__setattr__(Foo, 'class_attr', 'bar')

    #
    # Existing method on class
    #

    # protected by FauxImmutableMeta.__setattr__
    with pytest.raises(AttributeError, match='cannot set attribute `method` on faux-immutable class'):
        Foo.method = lambda self: None  # type: ignore[method-assign]

    # protected by FauxImmutableMeta.__setattr__
    with pytest.raises(AttributeError, match='cannot set attribute `method` on faux-immutable class'):
        setattr(Foo, 'method', lambda self: None)

    # protected by Python itself
    with pytest.raises(TypeError, match="can't apply this __setattr__ to FauxImmutableMeta object"):
        object.__setattr__(Foo, 'method', lambda self: None)

    #
    # Existing class method on class
    #

    # protected by FauxImmutableMeta.__setattr__
    with pytest.raises(AttributeError, match='cannot set attribute `class_method` on faux-immutable class'):
        Foo.class_method = lambda: None  # type: ignore[method-assign]

    # protected by FauxImmutableMeta.__setattr__
    with pytest.raises(AttributeError, match='cannot set attribute `class_method` on faux-immutable class'):
        setattr(Foo, 'class_method', lambda self: None)

    # protected by Python itself
    with pytest.raises(TypeError, match="can't apply this __setattr__ to FauxImmutableMeta object"):
        object.__setattr__(Foo, 'class_method', lambda self: None)

    #
    # New attribute on class
    #

    # protected by FauxImmutableMeta.__setattr__
    with pytest.raises(AttributeError, match='cannot set attribute `new_class_attr` on faux-immutable class'):
        Foo.new_class_attr = 'bar'

    # protected by FauxImmutableMeta.__setattr__
    with pytest.raises(AttributeError, match='cannot set attribute `new_class_attr` on faux-immutable class'):
        setattr(Foo, 'new_class_attr', 'bar')

    # protected by Python itself
    with pytest.raises(TypeError, match="can't apply this __setattr__ to FauxImmutableMeta object"):
        object.__setattr__(Foo, 'new_class_attr', 'bar')


def test_shell_class() -> None:
    class Foo(FauxImmutable):
        __slots__ = ()

    foo1 = create_with_shell(Foo)
    foo2 = create_with_shell(Foo)

    assert foo1.__class__ is not Foo
    assert foo1.__class__ != Foo

    assert foo2.__class__ is not Foo
    assert foo2.__class__ != Foo

    assert foo1.__class__ is not foo2.__class__
    assert foo1.__class__ != foo2.__class__
