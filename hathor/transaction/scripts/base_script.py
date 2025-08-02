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

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from enum import StrEnum, unique
from typing import Any, Optional


@unique
class ScriptType(StrEnum):
    P2PKH = 'P2PKH'
    MULTI_SIG = 'MultiSig'


@dataclass(slots=True, frozen=True, kw_only=True)
class ScriptInfo:
    type: ScriptType
    address: str
    timelock: int | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class BaseScript(ABC):
    """
    This class holds common methods for different script types to help abstracting the script type.
    """

    def get_info(self) -> ScriptInfo:
        """Return a human-readable dataclass."""
        from hathor.transaction.scripts import P2PKH, MultiSig
        match self:
            case P2PKH():
                type_ = ScriptType.P2PKH
            case MultiSig():
                type_ = ScriptType.MULTI_SIG
            case _:
                raise AssertionError(f'unknown script type {type(self)}')

        return ScriptInfo(
            type=type_,
            address=self.get_address(),
            timelock=self.get_timelock(),
        )

    @abstractmethod
    def get_script(self) -> bytes:
        """Get or build script"""
        raise NotImplementedError

    @abstractmethod
    def get_address(self) -> str:
        """Get address for this script."""
        raise NotImplementedError

    @abstractmethod
    def get_timelock(self) -> Optional[int]:
        """Get timelock for this script, completely optional."""
        raise NotImplementedError
