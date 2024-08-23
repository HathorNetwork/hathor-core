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
from dataclasses import dataclass
from typing import TypeAlias

from pydantic import Field
from typing_extensions import override

from hathor.utils.pydantic import BaseModel


@dataclass(frozen=True, slots=True)
class SighashAll:
    """A model representing the sighash all, which is the default sighash type."""
    pass


class CustomSighash(ABC, BaseModel):
    """An interface to be implemented by custom sighash models."""
    @abstractmethod
    def get_input_indexes(self) -> list[int]:
        """Return a list of input indexes selected by this sighash."""
        raise NotImplementedError

    @abstractmethod
    def get_output_indexes(self) -> list[int]:
        """Return a list of output indexes selected by this sighash."""
        raise NotImplementedError


class SighashBitmask(CustomSighash):
    """A model representing the sighash bitmask type config."""
    inputs: int = Field(ge=0x01, le=0xFF)
    outputs: int = Field(ge=0x00, le=0xFF)

    @override
    def get_input_indexes(self) -> list[int]:
        return self._get_indexes(self.inputs)

    @override
    def get_output_indexes(self) -> list[int]:
        return self._get_indexes(self.outputs)

    @staticmethod
    def _get_indexes(bitmask: int) -> list[int]:
        """Return a list of indexes equivalent to some bitmask."""
        return [index for index in range(8) if (bitmask >> index) & 1]


SighashType: TypeAlias = SighashAll | SighashBitmask


class InputsOutputsLimit(BaseModel):
    """A model representing inputs and outputs limits config."""
    max_inputs: int = Field(ge=1)
    max_outputs: int = Field(ge=1)
