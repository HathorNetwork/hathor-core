"""
Copyright (c) Hathor Labs and its affiliates.

This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
"""

import unittest

from hathorlib.base_transaction import TxOutput, tx_or_block_from_bytes


class HathorNFTTestCase(unittest.TestCase):
    def test_is_nft(self):
        # Normal tx
        data = bytes.fromhex('000100010100c994a3f1b46ddeb7134f65cb18b1b11ca7e19d59875a704b2bb2f79f6700b60000694630440'
                             '220066d379c43ee73c3704730a44d66a077fb2b1cee2b399cbcf87f34d2b2d84308022032e0a93662094c5d'
                             'b4ed022708981717d06038924535257d181c2fa9f62a6ff9210310a7cd9cae728ddf8c7fef342f963b1cab1'
                             '97d97b28124ebbd0208d60d9f08780000000200001976a914e7c8133e7611a0ef57830f4321661ff9e5c42f'
                             '4188ac40200000218def41612cefe10200002d0403a9e39e8176b2e8ca6728f7c8393cea3403f4432c047e5'
                             'b28cb0470009ed2ab70b799729bcdbaa8edc064bd78fb258ea23fe6688272acad587445ab0000000c')
        tx = tx_or_block_from_bytes(data)
        self.assertFalse(tx.is_nft_creation_standard())
        self.assertTrue(tx.is_standard())

        # Create token tx
        data2 = bytes.fromhex('0002010400b25b5385d9bbe80018a98884fdb2d63de3404c23e1b6695df34c103755b56900006a473045022'
                              '100b05b56237bd425ceeedc1bed82660239ae5cba5790e58980072a6d7a0b00ad500220729c456675abbee1'
                              '2b084ea841779ec26fe9d4ac4c3a6b2b004678ba697c66e72102c79cca85e51de1e3e85a232477d3be574aa'
                              '8d83c975321ac1993143d18401f3c0000006401001976a914bdd06a2ec4f180e5f3f5752671a771544c3936'
                              '4a88ac0000000181001976a914bdd06a2ec4f180e5f3f5752671a771544c39364a88ac0000000281001976a'
                              '914bdd06a2ec4f180e5f3f5752671a771544c39364a88ac0000138700001976a914439d757c69635d48ddb2'
                              'a106a18ea5c1ce158d8488ac0106544f4b454e3104544b4e314032320a39bd7d606127f3ff02009ed2ab70b'
                              '799729bcdbaa8edc064bd78fb258ea23fe6688272acad587445ab00d9741624399388d196e5e409595e65a1'
                              '803764ee078f34ebb2bda63ff6a63a000104d8')
        tx2 = tx_or_block_from_bytes(data2)
        self.assertFalse(tx2.is_nft_creation_standard())
        self.assertTrue(tx2.is_standard())

        # NFT tx
        data3 = bytes.fromhex('00020103000023117762f80fad7c28eea89e793036e8e5855038eee4deea02c53d7513e700006a473045022'
                              '100eab17bbadcd5297695847c7e81a9d9c8b7995b9816a8cb2db4f68721eef22d44022043e8b9498a557cd2'
                              'f8f4e957241cc78fee4daf0e149de5b9529048ee1ca0140e2103e42187c715fbdd129ef40bf9c6c9c63a6e0'
                              'd72d478d121fa23c6078fa5049457000000010000060454455354ac0000012c01001976a91495b3e7b7559a'
                              '2b1ffa6c337fc6aeff74e963796588ac0000000281001976a914e7b6fadc93b5553781d73ac908134c0bbc5'
                              '14e6b88ac01065465737474740354535440200000218def416127d5800200d9741624399388d196e5e40959'
                              '5e65a1803764ee078f34ebb2bda63ff6a63a001a2603c9a5947233dedb1160e9468e95563e76945ae58d829'
                              '118e17e668dc900000053')
        tx3 = tx_or_block_from_bytes(data3)
        self.assertTrue(tx3.is_nft_creation_standard())
        self.assertTrue(tx3.is_standard())

        # NFT custom tx with 2 data script outputs
        tx4 = tx_or_block_from_bytes(data3)
        # Add new data script output, creating a token creation tx with 2 script data outputs
        # This should be rejected as a standard NFT
        new_output = TxOutput(1, tx4.outputs[0].script, 0)
        tx4.outputs = [tx4.outputs[0], new_output] + tx4.outputs[1:]
        self.assertFalse(tx4.is_nft_creation_standard())
