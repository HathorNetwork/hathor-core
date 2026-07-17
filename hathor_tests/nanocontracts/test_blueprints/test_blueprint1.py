# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from hathor import Blueprint, Context, export, public, view


@export
class TestBlueprint1(Blueprint):
    @public
    def initialize(self, ctx: Context, a: int) -> None:
        pass

    @public
    def nop(self, ctx: Context) -> None:
        pass

    @view
    def view(self) -> None:
        pass

    @public
    def create_child_contract(self, ctx: Context) -> None:
        blueprint_id = self.syscall.get_blueprint_id()
        self.syscall.setup_new_contract(blueprint_id, salt=b'').initialize(0)
