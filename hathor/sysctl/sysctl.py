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

from typing import Any, Callable, Iterator, NamedTuple, Optional, ParamSpec, TypeVar

from pydantic import validate_call
from structlog import get_logger

from hathor.sysctl.exception import SysctlEntryNotFound, SysctlReadOnlyEntry, SysctlWriteOnlyEntry

Getter = Callable[[], Any]
Setter = Callable[..., None]
P = ParamSpec('P')
T = TypeVar('T')

logger = get_logger()


def signal_handler_safe(f: Callable[P, T]) -> Callable[P, T]:
    """Decorator to mark methods as signal handler safe.

    It should only be used if that method can be executed during a signal handling.
    Notice that a signal handling can pause the code execution at any point and the execution will resume after."""
    f._signal_handler_safe = True  # type: ignore[attr-defined]
    return f


class SysctlCommand(NamedTuple):
    getter: Optional[Getter]
    setter: Optional[Setter]


class Sysctl:
    """A node in the sysctl tree."""

    def __init__(self) -> None:
        self._children: dict[str, 'Sysctl'] = {}
        self._commands: dict[str, SysctlCommand] = {}
        self.log = logger.new()

    def put_child(self, path: str, sysctl: 'Sysctl') -> None:
        """Add a child to the tree."""
        assert path not in self._children
        self._children[path] = sysctl

    def register(self, path: str, getter: Optional[Getter], setter: Optional[Setter]) -> None:
        """Register a new parameter for sysctl."""
        assert path not in self._commands
        if setter is not None:
            setter = validate_call(setter)
        self._commands[path] = SysctlCommand(
            getter=getter,
            setter=setter,
        )

    def get_command(self, path: str) -> SysctlCommand:
        """Find and return the sysctl of the provided path."""
        if path in self._commands:
            return self._commands[path]
        for key, child in self._children.items():
            if not path.startswith(f'{key}.'):
                continue
            tail = path[len(key) + 1:]
            return child.get_command(tail)
        raise SysctlEntryNotFound(path)

    def get_getter(self, path: str) -> Getter:
        """Return the getter method of a path."""
        cmd = self.get_command(path)
        if cmd.getter is None:
            raise SysctlWriteOnlyEntry(path)
        return cmd.getter

    def get_setter(self, path: str) -> Setter:
        """Return the setter method of a path."""
        cmd = self.get_command(path)
        if cmd.setter is None:
            raise SysctlReadOnlyEntry(path)
        return cmd.setter

    def get(self, path: str) -> Any:
        """Run a get in sysctl."""
        getter = self.get_getter(path)
        return getter()

    def unsafe_set(self, path: str, value: Any) -> None:
        """Run a set in sysctl. You should use a runner instead of calling this method directly.
        Should not be called unless you know it's safe."""
        setter = self.get_setter(path)
        if isinstance(value, tuple):
            setter(*value)
        else:
            setter(value)

    def path_join(self, p1: str, p2: str) -> str:
        """Util to join two paths."""
        if not p1:
            return p2
        return f'{p1}.{p2}'

    def get_all(self, prefix: str = '') -> Iterator[tuple[str, Any]]:
        """Return all paths and values, usually for backup."""
        for path, child in self._children.items():
            yield from child.get_all(self.path_join(prefix, path))
        for path, cmd in self._commands.items():
            if cmd.getter is None:
                continue
            value = cmd.getter()
            yield (self.path_join(prefix, path), value)

    def get_all_paths(self, prefix: str = '') -> Iterator[str]:
        """Return all available paths."""
        for path, child in self._children.items():
            yield from child.get_all_paths(self.path_join(prefix, path))
        for path, cmd in self._commands.items():
            yield self.path_join(prefix, path)
