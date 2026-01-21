"""
Copyright (c) Hathor Labs and its affiliates.

This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
"""

import unittest

from hathorlib.base_transaction import TxOutput, tx_or_block_from_bytes
from hathorlib.conf import HathorSettings
from hathorlib.scripts import DataScript

settings = HathorSettings()


class HathorDataScriptTestCase(unittest.TestCase):
    def test_script_data(self):
        # Create NFT script data test
        data = 'nft data test'
        obj_data = DataScript(data)
        human = obj_data.to_human_readable()
        self.assertEqual(human['type'], 'Data')
        self.assertEqual(human['data'], data)

        script = obj_data.get_script()

        parsed_obj = DataScript.parse_script(script)
        self.assertEqual(parsed_obj.data, data)

        # Parse output script from real NFT
        data = bytes.fromhex('00020103000023117762f80fad7c28eea89e793036e8e5855038eee4deea02c53d7513e700006a473045022'
                             '100eab17bbadcd5297695847c7e81a9d9c8b7995b9816a8cb2db4f68721eef22d44022043e8b9498a557cd2'
                             'f8f4e957241cc78fee4daf0e149de5b9529048ee1ca0140e2103e42187c715fbdd129ef40bf9c6c9c63a6e0'
                             'd72d478d121fa23c6078fa5049457000000010000060454455354ac0000012c01001976a91495b3e7b7559a'
                             '2b1ffa6c337fc6aeff74e963796588ac0000000281001976a914e7b6fadc93b5553781d73ac908134c0bbc5'
                             '14e6b88ac01065465737474740354535440200000218def416127d5800200d9741624399388d196e5e40959'
                             '5e65a1803764ee078f34ebb2bda63ff6a63a001a2603c9a5947233dedb1160e9468e95563e76945ae58d829'
                             '118e17e668dc900000053')
        tx = tx_or_block_from_bytes(data)
        nft_script = DataScript.parse_script(tx.outputs[0].script)
        self.assertEqual(nft_script.data, 'TEST')

        self.assertFalse(tx.outputs[0].is_standard_script())
        self.assertTrue(tx.outputs[1].is_standard_script())

    def test_tx_with_script_data(self):
        # Parse output script from real test tx
        # This tx has a data script output and it's not an NFT creation tx
        data = bytes.fromhex('0001010202000041a564f1d090bbf23f7f370eee970ded2270aa2ff59e4632deb2a746d28500ff62bcebf5d'
                             'f2827d98f6f3113c1226d555d5cafc77b914e4411698c3382e503006a47304502205a984dab561ff8f97a4f'
                             'c09d889f844de4fb66b32edc19e77bd84e58fa91bd61022100ef6bfa2e6c8b7f8eb41561b9b012b60fc41a3'
                             '9742cea74c4e0152be3ff98cbc421026f9b6b0b5d3badb218999d865b47ca70dc052920ca663d13eecf3176'
                             '2ed308ee003d11dacb7449dc7caf081223cfefb571e3ae4ec60da8eb74a201d516f3f3da01006a473045022'
                             '05a984dab561ff8f97a4fc09d889f844de4fb66b32edc19e77bd84e58fa91bd61022100ef6bfa2e6c8b7f8e'
                             'b41561b9b012b60fc41a39742cea74c4e0152be3ff98cbc421026f9b6b0b5d3badb218999d865b47ca70dc0'
                             '52920ca663d13eecf31762ed308ee000000010000464468747470733a2f2f697066732e696f2f697066732f'
                             '516d586656704d6b52463475674254666a5361367a566f6e6d4b4a31466f6e43717434774d39354b5453463'
                             '756622fac0000000101001976a914aa8de9f415b80986c8827580d267ff963cca41e688ac40200000000000'
                             '00620bdc9702003d11dacb7449dc7caf081223cfefb571e3ae4ec60da8eb74a201d516f3f3da004aa11e1d1'
                             'bc4d2c7b26e4f1b42b6da66b2add6bd562e8f1f59ec25b005e7a20000001a')
        tx = tx_or_block_from_bytes(data)
        self.assertTrue(tx.is_standard())

        # Now we will add outputs until the max number of outputs
        number_of_data_script_outputs = 1

        while number_of_data_script_outputs < settings.MAX_DATA_SCRIPT_OUTPUTS:
            new_output = TxOutput(1, tx.outputs[0].script, 0)
            tx.outputs.append(new_output)
            self.assertTrue(tx.is_standard())
            number_of_data_script_outputs += 1

        # If we add one more, then it should become non standard
        new_output = TxOutput(1, tx.outputs[0].script, 0)
        tx.outputs.append(new_output)
        self.assertFalse(tx.is_standard())
