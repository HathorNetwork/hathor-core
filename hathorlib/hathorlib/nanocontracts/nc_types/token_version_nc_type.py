# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from typing_extensions import override

from hathorlib.nanocontracts.nc_types.sized_int_nc_type import Uint8NCType
from hathorlib.serialization import Deserializer
from hathorlib.token_info import TokenVersion


class TokenVersionNCType(Uint8NCType):
    @override
    def _deserialize(self, deserializer: Deserializer, /) -> TokenVersion:
        value = super()._deserialize(deserializer)
        return TokenVersion(value)
