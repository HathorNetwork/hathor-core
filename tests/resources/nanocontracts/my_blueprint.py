from typing import Optional

from hathor.nanocontracts import Blueprint
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.types import Address, Amount, SignedData, Timestamp, TokenUid, TxOutputScript, public, view


class MyBlueprint(Blueprint):
    a_int: int
    a_str: str
    a_bool: bool
    a_address: Address
    a_amount: Amount
    a_timestamp: Timestamp
    a_token_uid: TokenUid
    a_script: TxOutputScript
    a_signed_data: SignedData[str]
    a_dict: dict[str, int]
    a_tuple: tuple[str, int, bool]
    a_dict_dict_tuple: dict[str, tuple[str, int]]
    a_optional_int: Optional[int]

    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def nop(self, ctx: Context, arg1: int, arg2: SignedData[str]) -> None:
        """No operation."""
        self.a = arg1

    @view
    def my_private_method_nop(self, arg1: int) -> int:
        return 1

    @view
    def my_private_method_2(self) -> dict[dict[str, int], tuple[bool, str, int, int]]:
        return {}

    @view
    def my_private_method_3(self) -> list[str]:
        return []

    @view
    def my_private_method_4(self) -> set[int]:
        return set()

    @view
    def my_private_method_5(self) -> str | None:
        return None

    @view
    def my_private_method_6(self) -> None | str:
        return None

    @view
    def my_private_method_7(self) -> str | int | bool | None:
        return 0
