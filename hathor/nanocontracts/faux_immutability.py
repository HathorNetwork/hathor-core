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


class _FauxImmutabilityMeta(type):
    __slots__ = ()

    def __new__(cls, name, bases, attrs, **kwargs):
        if not attrs.get('__is_faux_immutable_base__', False) and not attrs.get('__is_shell__', False):
            cls.__validate(name, bases, attrs)
        return super().__new__(cls, name, bases, attrs, **kwargs)

    @staticmethod
    def __validate(name, bases, attrs):
        required_attrs = (
            '__slots__',
        )
        # TODO: Check all possible magic methods/attrs to add here
        prohibited_attrs = (
            '__new__',
            '__call__',
            '__setattr__',
            '__delattr__',
        )

        for attr in required_attrs:
            if attr not in attrs:
                raise TypeError(f'faux-immutable class `{name}` must define `{attr}`')

        for attr in prohibited_attrs:
            if attr in attrs:
                raise TypeError(f'faux-immutable class `{name}` must not define `{attr}`')

        # TODO
        assert len(bases) == 1
        assert bases[0] is FauxImmutable
        # for base in bases:
        #     if not type(base) is _FauxImmutabilityMeta:
        #         raise TypeError(
        #             f'faux-immutable class `{name}` cannot have non-faux-immutable base class `{base.__name__}`'
        #         )

    def __call__(cls, *args, **kwargs):
        name = cls.__name__
        bases = (cls,)
        attrs = dict(__slots__=(), __is_shell__=True)
        shell_type = type(name, bases, attrs)
        obj = cls.__new__(shell_type)
        shell_type.__init__(obj, *args, **kwargs)
        return obj

    def __setattr__(cls, name: str, value: object) -> None:
        raise AttributeError(f'cannot set attribute `{name}` on faux-immutable class')


class FauxImmutable(metaclass=_FauxImmutabilityMeta):
    __slots__ = ()
    __is_faux_immutable_base__: bool = True

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError(f'cannot set attribute `{name}` on faux-immutable object')


def __set_faux_immutable__(obj: FauxImmutable, name: str, value: object) -> None:
    if name.startswith('__') and not name.endswith('__'):
        name = f'_{obj.__class__.__name__}{name}'
    object.__setattr__(obj, name, value)
