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

from collections import OrderedDict
from typing import NamedTuple, Optional, Union

from hathor import (
    Address,
    Amount,
    Blueprint,
    BlueprintId,
    Context,
    ContractId,
    SignedData,
    Timestamp,
    TokenUid,
    TxOutputScript,
    VertexId,
    public,
)


class MyTuple(NamedTuple):
    a: int
    b: str


class AllFieldsBlueprint(Blueprint):
    attribute1: OrderedDict[str, int]
    attribute2: list[int]
    attribute3: set[int]
    attribute4: bool
    attribute5: bytes
    attribute6: dict[str, int]
    attribute7: frozenset[int]
    attribute8: int
    attribute9: str
    attribute10: dict[str, tuple[int]]
    attribute11: tuple[str, int]
    attribute12: tuple[str, ...]
    attribute13: Union[str, None]
    attribute14: Optional[str]
    attribute15: str | None
    attribute16: None | str
    attribute17: Address
    attribute18: Amount
    attribute19: BlueprintId
    attribute20: ContractId
    attribute21: Timestamp
    attribute22: TokenUid
    attribute23: TxOutputScript
    attribute24: VertexId
    attribute25: SignedData[str]
    attribute26: MyTuple

    @public
    def initialize(self, ctx: Context) -> None:
        pass
