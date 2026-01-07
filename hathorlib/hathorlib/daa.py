# Copyright (c) Hathor Labs and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

from math import log
from typing import TYPE_CHECKING

from hathorlib.conf import HathorSettings

if TYPE_CHECKING:
    from hathorlib import Transaction

settings = HathorSettings()


def minimum_tx_weight(tx: 'Transaction', *, fix_parents: bool = True) -> float:
    """Return the minimum weight for the tx.

       The minimum is calculated by the following function:

       w = alpha * log(size, 2) +       4.0         + 4.0
                                  ----------------
                                   1 + k / amount
    """
    tx_size = len(tx.get_struct())

    # When a transaction is still being create, it might not have its parents yet.
    # In this case, the parents will be added later but we need to take their size
    # into consideration to calculate the weight.
    if fix_parents and len(tx.parents) < 2:
        tx_size += 32 * (2 - len(tx.parents))

    # We need to take into consideration the decimal places because it is inside the amount.
    # For instance, if one wants to transfer 20 HTRs, the amount will be 2000.
    # Max below is preventing division by 0 when handling authority methods that have no outputs
    amount = max(1, tx.sum_outputs) / (10 ** settings.DECIMAL_PLACES)

    weight: float = (
        + settings.MIN_TX_WEIGHT_COEFFICIENT * log(tx_size, 2)
        + 4 / (1 + settings.MIN_TX_WEIGHT_K / amount) + 4
    )

    # Make sure the calculated weight is at least the minimum
    weight = max(weight, settings.MIN_TX_WEIGHT)

    return weight
