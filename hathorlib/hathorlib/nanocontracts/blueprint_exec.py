#  Copyright 2026 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, TypeVar, TypeVarTuple, Unpack

from typing_extensions import Protocol

from hathorlib.nanocontracts.blueprint import Blueprint
from hathorlib.nanocontracts.cpython_executor import CPythonExecutor
from hathorlib.nanocontracts.types import BLUEPRINT_EXPORT_NAME

if TYPE_CHECKING:
    from hathor.nanocontracts import OnChainBlueprint  # type: ignore[import-not-found]


T = TypeVar('T')
Ts = TypeVarTuple('Ts')


@dataclass(slots=True, frozen=True, kw_only=True)
class UsageLimits:
    compute: int
    memory: int


MAX_USAGE_FOR_VERIFICATION_EXEC = UsageLimits(compute=0, memory=0)
MAX_USAGE_FOR_API_EXEC = UsageLimits(compute=0, memory=0)
MAX_USAGE_FOR_CONSENSUS_METHOD_CALL = UsageLimits(compute=0, memory=0)
MAX_USAGE_FOR_API_METHOD_CALL = UsageLimits(compute=0, memory=0)
MAX_USAGE_FOR_JSON_SERIALIZER = UsageLimits(compute=0, memory=0)


class SandboxedExecutor(Protocol):
    """Represents classes that can exec/call Python source code in a sandboxed and metered environment."""
    def exec(self, source: str, /) -> dict[str, object]: ...
    def call(self, func: Callable[[Unpack[Ts]], T], /, *, args: tuple[Unpack[Ts]]) -> T: ...


def create_sandbox(usage_limits: UsageLimits) -> SandboxedExecutor:
    """Create a sandboxed environment for Python code execution, with compute and memory limits."""
    return CPythonExecutor()


def create_sandbox_for_verification_exec() -> SandboxedExecutor:
    """
    Create a sandboxed environment for Python code execution,
    with compute and memory limits set for a verification execution.
    """
    return create_sandbox(MAX_USAGE_FOR_VERIFICATION_EXEC)


def create_sandbox_for_api_exec() -> SandboxedExecutor:
    """
    Create a sandboxed environment for Python code execution,
    with compute and memory limits set for a method call.
    """
    return create_sandbox(MAX_USAGE_FOR_API_EXEC)


def create_sandbox_for_consensus_method_call() -> SandboxedExecutor:
    """
    Create a sandboxed environment for Python code execution,
    with compute and memory limits set for a method call during the consensus.
    """
    return create_sandbox(MAX_USAGE_FOR_CONSENSUS_METHOD_CALL)


def create_sandbox_for_api_method_call() -> SandboxedExecutor:
    """
    Create a sandboxed environment for Python code execution,
    with compute and memory limits set for a method call on an API.
    """
    return create_sandbox(MAX_USAGE_FOR_API_METHOD_CALL)


def create_sandbox_for_json_serializer() -> SandboxedExecutor:
    """
    Create a sandboxed environment for Python code execution,
    with compute and memory limits set for a JSON serializer.
    """
    return create_sandbox(MAX_USAGE_FOR_JSON_SERIALIZER)


def exec_ocb_module_unchecked(
    sandboxed_executor: SandboxedExecutor,
    ocb: OnChainBlueprint,
) -> tuple[object, dict[str, object]]:
    """Exec an OCB module and return its env and unchecked class."""
    env = sandboxed_executor.exec(ocb.code.text)
    blueprint_class = env[BLUEPRINT_EXPORT_NAME]
    return blueprint_class, env


def exec_ocb_module_checked(
    sandboxed_executor: SandboxedExecutor,
    ocb: OnChainBlueprint,
) -> tuple[type[Blueprint], dict[str, object]]:
    """Exec an OCB module and return its env and checked class."""
    blueprint_class, env = exec_ocb_module_unchecked(sandboxed_executor, ocb)
    assert isinstance(blueprint_class, type)
    assert issubclass(blueprint_class, Blueprint)
    return blueprint_class, env


def exec_ocb_class_unchecked(
    sandboxed_executor: SandboxedExecutor,
    ocb: OnChainBlueprint,
) -> object:
    """Exec an OCB module and return its unchecked class."""
    blueprint_class, _ = exec_ocb_module_unchecked(sandboxed_executor, ocb)
    return blueprint_class


def exec_ocb_class_checked(
    sandboxed_executor: SandboxedExecutor,
    ocb: OnChainBlueprint,
) -> type[Blueprint]:
    """Exec an OCB module and return its checked class."""
    blueprint_class, _ = exec_ocb_module_checked(sandboxed_executor, ocb)
    return blueprint_class
