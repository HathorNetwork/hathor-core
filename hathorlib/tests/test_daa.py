# Copyright (c) Hathor Labs and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

import unittest

from hathorlib import Transaction
from hathorlib.daa import minimum_tx_weight


class HathorDAATestCase(unittest.TestCase):
    def test_address_from_pubkey(self):
        tx_bytes = bytes.fromhex(
            '0001000102000000004b9f8c309247d44d8f242252516eff16cd4a4b6c7dfab2eea05a8a3101006a4730450'
            '22100b5ccb3f4e2ebd5a16a6bdf14e0d392f0f02429f52c6260a14e79da1e1841fc58022048177cf5b0479f'
            '37ff5c907a2e75cc1e0ba257608fb4156dad4d57143b60d7c52103548024000a2f7974de7abf7a391ec2552'
            'd653d460153bff2aaa2885b6612eb9c000041e300001976a914555ccdd5fbd8286b10afe5d5f49d4be6db25'
            '113e88ac0000006400001976a91471fe2456c0dc242a022478d4928707c4720943a588ac40339ccd44c989a'
            'f6056491602000000009e59fbcbdaffc47b564b43af41f395a65b4eabb9e7667d6ad5ce2af6000002c69153'
            '8af910fc12d475f5fd468bf4a50ecd89b08cdd1bf82a355444b1541e5618'
        )
        tx = Transaction.create_from_struct(tx_bytes)
        min_tx_weight = minimum_tx_weight(tx)
        self.assertAlmostEqual(tx.weight, min_tx_weight, places=4)

        tx.parents = []
        min_tx_weight2 = minimum_tx_weight(tx)
        self.assertAlmostEqual(min_tx_weight, min_tx_weight2)

        min_tx_weight3 = minimum_tx_weight(tx, fix_parents=False)
        self.assertNotAlmostEqual(min_tx_weight, min_tx_weight3)
