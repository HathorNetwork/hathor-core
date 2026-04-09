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

from hathor import Address, Blueprint, Context, NCFail, export, public, view


@export
class AddressExample(Blueprint):
    """Dummy blueprint to test the exposed API.

    This blueprint is very limited, but eventually it should test all API that is exposed.
    """

    last_address: Address | None

    @public
    def initialize(self, ctx: Context) -> None:
        caller_address = ctx.get_caller_address()
        if caller_address is None:
            raise NCFail('must be initialized from address, not from a contract')
        self.last_address = caller_address

    @view
    def get_last_address_str(self) -> str:
        return str(self.last_address)

    @public
    def set_last_address_from_str(self, ctx: Context, address: str) -> None:
        self.last_address = Address.from_str(address)
