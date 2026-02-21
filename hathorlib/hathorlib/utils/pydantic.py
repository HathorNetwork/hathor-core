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

from typing import TYPE_CHECKING, Annotated, Any, TypeVar

from pydantic import BaseModel as PydanticBaseModel, ConfigDict
from pydantic.functional_serializers import PlainSerializer
from pydantic.functional_validators import BeforeValidator

BytesT = TypeVar('BytesT', bound=bytes)


def _hex_to_bytes(value: Any) -> bytes:
    """Convert hex string to bytes, or pass through if already bytes."""
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return bytes.fromhex(value)
    raise ValueError(f'Expected bytes or hex string, got {type(value).__name__}')


def _bytes_to_hex(value: bytes) -> str:
    """Convert bytes to hex string."""
    return value.hex()


if TYPE_CHECKING:
    # For type checking: Hex[T] is just T (an identity type alias)
    # This allows mypy to treat Hex[VertexId] as VertexId
    Hex = Annotated[BytesT, ...]
else:
    # At runtime: Hex[T] returns Annotated[T, validators, serializers]
    # Pydantic uses this for automatic hex encoding/decoding
    #
    # Usage:
    #     from hathorlib.types import VertexId, ContractId
    #     from hathorlib.utils.pydantic import Hex
    #
    #     class MyModel(BaseModel):
    #         tx_id: Hex[VertexId]           # Preserves VertexId type
    #         contract: Hex[ContractId]       # Preserves ContractId type
    #         items: list[Hex[VertexId]]      # Works with generic types too
    #
    # Behavior:
    #     - Deserialization: Accepts both bytes and hex str, converts to the base type
    #     - Serialization: Always outputs as hex string in JSON

    class _HexMeta(type):
        """Metaclass that makes Hex[T] return Annotated[bytes, ...] at runtime.

        We use `bytes` as the base type for Pydantic schema generation because
        Pydantic v2 doesn't know how to handle custom bytes subclasses like
        ContractId or VertexId. The validators/serializers handle the conversion.
        """

        def __getitem__(cls, base_type: type[BytesT]) -> type[BytesT]:
            return Annotated[  # type: ignore[return-value]
                bytes,
                BeforeValidator(_hex_to_bytes),
                PlainSerializer(_bytes_to_hex, return_type=str),
            ]

    class Hex(metaclass=_HexMeta):
        """Hex[T] wraps a bytes-derived type to enable hex serialization."""
        pass


class BaseModel(PydanticBaseModel):
    """Substitute for pydantic's BaseModel.
    This class defines a project BaseModel to be used instead of pydantic's, setting stricter global configurations.
    Other configurations can be set on a case by case basis.

    Read: https://docs.pydantic.dev/latest/concepts/config/
    """
    model_config = ConfigDict(extra='forbid', frozen=True)

    def json_dumpb(self) -> bytes:
        """Utility method for converting a Model into bytes representation of a JSON."""
        return self.model_dump_json().encode('utf-8')
