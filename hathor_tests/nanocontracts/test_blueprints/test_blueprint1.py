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
        self.syscall.setup_new_contract(blueprint_id, salt=b'child').initialize(0)
