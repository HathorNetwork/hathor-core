from hathor.nanocontracts import Blueprint
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.types import public


class TestBlueprint(Blueprint):
    """ This class is used by the test for the blueprint source code resource
        It must be in a separate file for the assert in the test
    """
    int_attribute: int

    @public
    def initialize(self, ctx: Context) -> None:
        self.int_attribute = 0

    @public
    def sum(self, ctx: Context, arg1: int) -> None:
        self.int_attribute += arg1
