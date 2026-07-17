# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

# mypy: disable-error-code="attr-defined"

import unittest

from hathorlib.nanocontracts.faux_immutable import FauxImmutable, __set_faux_immutable__, create_with_shell


class TestFauxImmutable(unittest.TestCase):
    def test_basic_immutable_class(self) -> None:
        class MyClass(FauxImmutable):
            __slots__ = ('_value',)

            def __init__(self, value: int) -> None:
                __set_faux_immutable__(self, '_value', value)

        obj = MyClass(42)
        self.assertEqual(obj._value, 42)

    def test_setattr_raises(self) -> None:
        class MyClass(FauxImmutable):
            __slots__ = ('_value',)

            def __init__(self, value: int) -> None:
                __set_faux_immutable__(self, '_value', value)

        obj = MyClass(42)
        with self.assertRaises(AttributeError):
            obj._value = 99

    def test_class_setattr_raises(self) -> None:
        class MyClass(FauxImmutable):
            __slots__ = ()

        with self.assertRaises(AttributeError):
            MyClass.foo = 'bar'

    def test_missing_slots_raises(self) -> None:
        with self.assertRaises(TypeError):
            class BadClass(FauxImmutable):
                pass

    def test_dunder_forbidden(self) -> None:
        with self.assertRaises(TypeError):
            class BadClass(FauxImmutable):
                __slots__ = ()

                def __len__(self) -> int:
                    return 0

    def test_allowed_dunder(self) -> None:
        class MyClass(FauxImmutable):
            __slots__ = ()
            __allow_faux_dunder__ = ('__str__',)

            def __str__(self) -> str:
                return 'hello'

        obj = MyClass()
        self.assertEqual(str(obj), 'hello')

    def test_create_with_shell(self) -> None:
        class MyClass(FauxImmutable):
            __slots__ = ('_value',)
            __allow_faux_inheritance__ = True

            def __init__(self, value: int) -> None:
                __set_faux_immutable__(self, '_value', value)

        obj = create_with_shell(MyClass, 42)
        self.assertEqual(obj._value, 42)
        self.assertIsInstance(obj, MyClass)

    def test_multiple_bases_forbidden(self) -> None:
        with self.assertRaises(TypeError):
            class Base1(FauxImmutable):
                __slots__ = ()
                __allow_faux_inheritance__ = True

            class Base2(FauxImmutable):
                __slots__ = ()
                __allow_faux_inheritance__ = True

            class BadClass(Base1, Base2):
                __slots__ = ()

    def test_indirect_inheritance_raises(self) -> None:
        class Base(FauxImmutable):
            __slots__ = ()

        with self.assertRaises(TypeError):
            class Child(Base):
                __slots__ = ()
