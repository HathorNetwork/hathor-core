# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

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
