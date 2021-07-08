from twisted.internet.defer import inlineCallbacks

from hathor.transaction import Transaction
from hathor.transaction.resources import TransactionResource
from tests.resources.base_resource import StubSite, _BaseResourceTest
from tests.utils import add_blocks_unlock_reward, add_new_blocks, add_new_transactions


class TransactionTest(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp()
        self.web = StubSite(TransactionResource(self.manager))
        self.manager.wallet.unlock(b'MYPASS')

    @inlineCallbacks
    def test_get_one(self):
        genesis_tx = next(x for x in self.manager.tx_storage.get_all_genesis() if x.is_block)
        response_success = yield self.web.get("transaction", {b'id': bytes(genesis_tx.hash.hex(), 'utf-8')})
        data_success = response_success.json_value()
        self.assertTrue(data_success['success'])
        dict_test = genesis_tx.to_json(decode_script=True)
        dict_test['raw'] = genesis_tx.get_struct().hex()
        dict_test['nonce'] = str(dict_test['nonce'])
        if genesis_tx.is_block:
            dict_test['height'] = genesis_tx.calculate_height()
        self.assertEqual(data_success['tx'], dict_test)

        # Test sending hash that does not exist
        response_error1 = yield self.web.get(
            "transaction", {b'id': b'000000831cff82fa730cbdf8640fae6c130aab1681336e2f8574e314a5533848'})
        data_error1 = response_error1.json_value()
        self.assertFalse(data_error1['success'])

        # Test sending invalid hash
        response_error2 = yield self.web.get(
            "transaction", {b'id': b'000000831cff82fa730cbdf8640fae6c130aab1681336e2f8574e314a553384'})
        data_error2 = response_error2.json_value()
        self.assertFalse(data_error2['success'])

        # Adding blocks to have funds
        add_new_blocks(self.manager, 2, advance_clock=1)
        add_blocks_unlock_reward(self.manager)
        tx = add_new_transactions(self.manager, 1)[0]

        tx2 = Transaction.create_from_struct(tx.get_struct())
        tx2.parents = [tx.parents[1], tx.parents[0]]
        tx2.resolve()

        self.manager.propagate_tx(tx2)

        # Now we get a tx with conflict, voided_by and twin
        response_conflict = yield self.web.get("transaction", {b'id': bytes(tx2.hash.hex(), 'utf-8')})
        data_conflict = response_conflict.json_value()
        self.assertTrue(data_conflict['success'])

    @inlineCallbacks
    def test_get_one_known_tx(self):
        # Tx tesnet 0033784bc8443ba851fd88d81c6f06774ae529f25c1fa8f026884ad0a0e98011
        # We had a bug with this endpoint in this tx because the token_data from inputs
        # was being copied from the output

        # First add needed data on storage
        tx_hex = ('0001020306001c382847d8440d05da95420bee2ebeb32bc437f82a9ae47b0745c8a29a7b0d007231eee3cb6160d95172'
                  'a409d634d0866eafc8775f5729fff6a61e7850aba500f4dd53f84f1f0091125250b044e49023fbbd0f74f6093cdd2226'
                  'fdff3e09a101006946304402205dcbb7956d95b0e123954160d369e64bca7b176e1eb136e2dae5b95e46741509022072'
                  '6f99a363e8a4d79963492f4359c7589667eb0f45af7effe0dd4e51fbb5543d210288c10b8b1186b8c5f6bc05855590a6'
                  '522af35f269ddfdb8df39426a01ca9d2dd003d3c40fb04737e1a2a848cfd2592490a71cd0248b9e7d6a626f45dec8697'
                  '5b00006a4730450221008741dff52d97ce5f084518e1f4cac6bd98abdc88b98e6b18d6a8666fadac05f0022068951306'
                  '19eaf5433526e4803187c0aa08a8b1c46d9dc4ffaa89406fb2d4940c2102dd29eaadbb21a4de015d1812d5c0ec63cb8e'
                  'e921e28580b6a9f8ff08db168c0e0096fb9b1a9e5fc34a9750bcccc746564c2b73f6defa381e130d9a4ea38cb1d80000'
                  '6a473045022100cb6b8abfb958d4029b0e6a89c828b65357456d20b8e6a8e42ad6d9a780fcddc4022035a8a46248b9c5'
                  '20b0205aa99ec5c390b40ae97a0b3ccc6e68e835ce5bde972a210306f7fdc08703152348484768fc7b85af900860a3d6'
                  'fa85343524150d0370770b0000000100001976a914b9987a3866a7c26225c57a62b14e901377e2f9e288ac0000000200'
                  '001976a914b9987a3866a7c26225c57a62b14e901377e2f9e288ac0000000301001f0460b5a2b06f76a914b9987a3866'
                  'a7c26225c57a62b14e901377e2f9e288ac0000006001001976a914b9987a3866a7c26225c57a62b14e901377e2f9e288'
                  'ac0000000402001976a914b9987a3866a7c26225c57a62b14e901377e2f9e288ac000002b602001976a91479ae26cf2f'
                  '2dc703120a77192fc16eda9ed22e1b88ac40200000218def416095b08602003d3c40fb04737e1a2a848cfd2592490a71cd'
                  '0248b9e7d6a626f45dec86975b00f4dd53f84f1f0091125250b044e49023fbbd0f74f6093cdd2226fdff3e09a1000002be')
        tx = Transaction.create_from_struct(bytes.fromhex(tx_hex), self.manager.tx_storage)
        self.manager.tx_storage.save_transaction(tx)

        tx_parent1_hex = ('0001010102001c382847d8440d05da95420bee2ebeb32bc437f82a9ae47b0745c8a29a7b0d001c382847d844'
                          '0d05da95420bee2ebeb32bc437f82a9ae47b0745c8a29a7b0d010069463044022018d530dbf9b5ff9bfc5522'
                          '156bd1cc0640843f14aa6b1f5bfaf4d56a7afb9bb7022074295ddfbe29314cc137451fc69445fe6f120a174b'
                          '0b8d97deb7115122fa4429210294fa8193a4b7116c4c27964f41adfd8ffac599e950de3189816bca59fe3a16'
                          '3a0000006301001976a91466c5bf509661f53f009321b031299d0bc32a192a88ac0000000101001976a91466'
                          'c5bf509661f53f009321b031299d0bc32a192a88ac40200000218def416095ae650200f4dd53f84f1f009112'
                          '5250b044e49023fbbd0f74f6093cdd2226fdff3e09a1001f16fe62e3433bcc74b262c11a1fa94fcb38484f4d'
                          '8fb080f53a0c9c57ddb000000120')
        tx_parent1 = Transaction.create_from_struct(bytes.fromhex(tx_parent1_hex), self.manager.tx_storage)
        self.manager.tx_storage.save_transaction(tx_parent1)

        tx_parent2_hex = ('0001000103001f16fe62e3433bcc74b262c11a1fa94fcb38484f4d8fb080f53a0c9c57ddb001006946304402'
                          '2001fe05a857825e3f25eaf93a983cf599ab351bef7a5829793d7158deddc1352002200bc9271590fc61b3e9'
                          'cf4e1aacc6b1cc44f5dc197c4ad938472f0a4107957ebf210230b8681ea0b03291f90cf846c49f122a80b802'
                          'db37662f8b816072f7fdec9c900000000200001976a91434b13dc4351400faf5025bd29d6ddcc0a98366d188'
                          'ac0000000300001976a91434b13dc4351400faf5025bd29d6ddcc0a98366d188ac0000000100001f0460b5a2'
                          'b06f76a91434b13dc4351400faf5025bd29d6ddcc0a98366d188ac40200000218def416095a16502001f16fe'
                          '62e3433bcc74b262c11a1fa94fcb38484f4d8fb080f53a0c9c57ddb00065329457d13410ac711318bd941e16'
                          'd57709926b76e64763bf19c3f13eeac30000016d')
        tx_parent2 = Transaction.create_from_struct(bytes.fromhex(tx_parent2_hex), self.manager.tx_storage)
        self.manager.tx_storage.save_transaction(tx_parent2)

        tx_input_hex = ('0001010203007231eee3cb6160d95172a409d634d0866eafc8775f5729fff6a61e7850aba500b3ab76c5337b55'
                        'a8346a3c43ba2776dd63d1dca324f1714eb349c4cc3819b601006a473045022100ceb28c367719233c7f72b17c'
                        'dc662352f8e1abee82daa34a1ed159a1afb0ac88022006cf505ce28fed9bdfe3e095df25e484677d5333df9203'
                        '6a2e4c5c49bdac5f1321027148251734ddcf20d338ff5c84fdd57a29986591c741bf2da2c6f7bb5e9768ca00b3'
                        'ab76c5337b55a8346a3c43ba2776dd63d1dca324f1714eb349c4cc3819b600006a47304502210099561d029914'
                        '0c8fa20fd6e42a615f5c93805d14001e8179a20ecd8d016e99b102202f6e6a66aef3a33c91a1cb64e82ffb40a2'
                        'c8fa62ef05d8d4b7e5932150188c122103318d7ea94afa2141f9ff815de6c257cbaf0aa1261621269c5f0ec7a5'
                        'aa793c24000002ba01001976a9147f651f9ce534e2a7e75286753fc48d3e4eadf76988ac0000000281001976a9'
                        '14b098e763d0d5e3017022389b38955e339a485df688ac0000000100001976a914cec7c7f37a01b66dc63776a2'
                        '5e95ac369b31f46188ac40200000218def416082eba802000e4e54b2922c1fa34b5d427f1e96885612e28673ac'
                        'cfaf6e7ceb2ba91c9c84009c8174d4a46ebcc789d1989e3dec5b68cffeef239fd8cf86ef62728e2eacee000001b6')
        tx_input = Transaction.create_from_struct(bytes.fromhex(tx_input_hex), self.manager.tx_storage)
        self.manager.tx_storage.save_transaction(tx_input)

        token_bytes1 = bytes.fromhex('001c382847d8440d05da95420bee2ebeb32bc437f82a9ae47b0745c8a29a7b0d')
        status = self.manager.tx_storage.tokens_index.tokens[token_bytes1]
        status.name = 'Test Coin'
        status.symbol = 'TSC'

        token_bytes2 = bytes.fromhex('007231eee3cb6160d95172a409d634d0866eafc8775f5729fff6a61e7850aba5')
        status2 = self.manager.tx_storage.tokens_index.tokens[token_bytes2]
        status2.name = 'NewCoin'
        status2.symbol = 'NCN'

        response = yield self.web.get(
            "transaction", {b'id': b'0033784bc8443ba851fd88d81c6f06774ae529f25c1fa8f026884ad0a0e98011'})
        data = response.json_value()
        print('data', data)

        self.assertEqual(len(data['tx']['inputs']), 3)
        self.assertEqual(len(data['tx']['outputs']), 6)
        self.assertEqual(len(data['tx']['tokens']), 2)

        # Inputs token data
        self.assertEqual(data['tx']['inputs'][0]['token_data'], 0)
        self.assertEqual(data['tx']['inputs'][0]['decoded']['token_data'], 0)
        self.assertEqual(data['tx']['inputs'][1]['token_data'], 1)
        self.assertEqual(data['tx']['inputs'][1]['decoded']['token_data'], 1)
        self.assertEqual(data['tx']['inputs'][2]['token_data'], 2)
        self.assertEqual(data['tx']['inputs'][2]['decoded']['token_data'], 2)

        # Outputs token data
        self.assertEqual(data['tx']['outputs'][0]['token_data'], 0)
        self.assertEqual(data['tx']['outputs'][0]['decoded']['token_data'], 0)
        self.assertEqual(data['tx']['outputs'][1]['token_data'], 0)
        self.assertEqual(data['tx']['outputs'][1]['decoded']['token_data'], 0)
        self.assertEqual(data['tx']['outputs'][2]['token_data'], 1)
        self.assertEqual(data['tx']['outputs'][2]['decoded']['token_data'], 1)
        self.assertEqual(data['tx']['outputs'][3]['token_data'], 1)
        self.assertEqual(data['tx']['outputs'][3]['decoded']['token_data'], 1)
        self.assertEqual(data['tx']['outputs'][4]['token_data'], 2)
        self.assertEqual(data['tx']['outputs'][4]['decoded']['token_data'], 2)
        self.assertEqual(data['tx']['outputs'][5]['token_data'], 2)
        self.assertEqual(data['tx']['outputs'][5]['decoded']['token_data'], 2)

    @inlineCallbacks
    def test_get_many(self):
        # Add some blocks and txs and get them in timestamp order
        blocks = add_new_blocks(self.manager, 4, advance_clock=1)
        _blocks = add_blocks_unlock_reward(self.manager)
        txs = sorted(add_new_transactions(self.manager, 25), key=lambda x: (x.timestamp, x.hash))

        blocks.extend(_blocks)
        blocks = sorted(blocks, key=lambda x: (x.timestamp, x.hash))

        # Get last 2 blocks
        expected1 = blocks[-2:]
        expected1.reverse()

        response1 = yield self.web.get("transaction", {b'count': b'2', b'type': b'block'})
        data1 = response1.json_value()

        for expected, result in zip(expected1, data1['transactions']):
            self.assertEqual(expected.timestamp, result['timestamp'])
            self.assertEqual(expected.hash.hex(), result['tx_id'])

        self.assertTrue(data1['has_more'])

        # Get last 8 txs
        expected2 = txs[-8:]
        expected2.reverse()

        response2 = yield self.web.get("transaction", {b'count': b'8', b'type': b'tx'})
        data2 = response2.json_value()

        for expected, result in zip(expected2, data2['transactions']):
            self.assertEqual(expected.timestamp, result['timestamp'])
            self.assertEqual(expected.hash.hex(), result['tx_id'])

        self.assertTrue(data2['has_more'])

        # Get older blocks with hash reference
        expected3 = blocks[:2]
        expected3.reverse()

        response3 = yield self.web.get(
            "transaction", {
                b'count': b'3',
                b'type': b'block',
                b'timestamp': bytes(str(blocks[2].timestamp), 'utf-8'),
                b'hash': bytes(blocks[2].hash.hex(), 'utf-8'),
                b'page': b'next'
            })
        data3 = response3.json_value()

        for expected, result in zip(expected3, data3['transactions']):
            self.assertEqual(expected.timestamp, result['timestamp'])
            self.assertEqual(expected.hash.hex(), result['tx_id'])

        self.assertFalse(data3['has_more'])

        # Get newer txs with hash reference
        response4 = yield self.web.get(
            "transaction", {
                b'count': b'16',
                b'type': b'tx',
                b'timestamp': bytes(str(txs[-9].timestamp), 'utf-8'),
                b'hash': bytes(txs[-9].hash.hex(), 'utf-8'),
                b'page': b'previous'
            })
        data4 = response4.json_value()

        for expected, result in zip(expected2, data4['transactions']):
            self.assertEqual(expected.timestamp, result['timestamp'])
            self.assertEqual(expected.hash.hex(), result['tx_id'])

        self.assertFalse(data4['has_more'])

        # Get newer blocks with hash reference
        expected5 = blocks[-2:]
        expected5.reverse()

        response5 = yield self.web.get(
            "transaction", {
                b'count': b'3',
                b'type': b'block',
                b'timestamp': bytes(str(expected1[-1].timestamp), 'utf-8'),
                b'hash': bytes(expected1[-1].hash.hex(), 'utf-8'),
                b'page': b'previous'
            })
        data5 = response5.json_value()

        for expected, result in zip(expected5, data5['transactions']):
            self.assertEqual(expected.timestamp, result['timestamp'])
            self.assertEqual(expected.hash.hex(), result['tx_id'])

        self.assertFalse(data5['has_more'])

        # Get txs with hash reference
        expected6 = txs[:8]
        expected6.reverse()

        response6 = yield self.web.get(
            "transaction", {
                b'count': b'8',
                b'type': b'tx',
                b'timestamp': bytes(str(txs[8].timestamp), 'utf-8'),
                b'hash': bytes(txs[8].hash.hex(), 'utf-8'),
                b'page': b'next'
            })
        data6 = response6.json_value()

        for expected, result in zip(expected6, data6['transactions']):
            self.assertEqual(expected.timestamp, result['timestamp'])
            self.assertEqual(expected.hash.hex(), result['tx_id'])

        self.assertTrue(data6['has_more'])

    @inlineCallbacks
    def test_invalid_params(self):
        # Add some blocks and txs
        add_new_blocks(self.manager, 4, advance_clock=1)
        add_blocks_unlock_reward(self.manager)
        add_new_transactions(self.manager, 3)

        # invalid count
        response = yield self.web.get("transaction", {b'count': b'a', b'type': b'block'})
        data = response.json_value()
        self.assertFalse(data['success'])

        # missing type
        response = yield self.web.get("transaction", {b'count': b'3'})
        data = response.json_value()
        self.assertFalse(data['success'])

        # invalid type
        response = yield self.web.get("transaction", {b'count': b'3', b'type': b'block1'})
        data = response.json_value()
        self.assertFalse(data['success'])

        # missing timestamp
        response = yield self.web.get(
                "transaction", {
                    b'count': b'3',
                    b'type': b'block',
                    b'hash': bytes('0000000043bae7193ae512e8e6e6cd666ef3ea46db6df63bd22f201c5fd682ea', 'utf-8')
                })
        data = response.json_value()
        self.assertFalse(data['success'])

        # invalid timestamp
        response = yield self.web.get(
                "transaction", {
                    b'count': b'3',
                    b'type': b'block',
                    b'hash': bytes('0000000043bae7193ae512e8e6e6cd666ef3ea46db6df63bd22f201c5fd682ea', 'utf-8'),
                    b'timestamp': b'aa'
                })
        data = response.json_value()
        self.assertFalse(data['success'])

        # missing page
        response = yield self.web.get(
                "transaction", {
                    b'count': b'3',
                    b'type': b'block',
                    b'hash': bytes('0000000043bae7193ae512e8e6e6cd666ef3ea46db6df63bd22f201c5fd682ea', 'utf-8'),
                    b'timestamp': b'1579716659'
                })
        data = response.json_value()
        self.assertFalse(data['success'])

        # invalid timestamp
        response = yield self.web.get(
                "transaction", {
                    b'count': b'3',
                    b'type': b'block',
                    b'hash': bytes('0000000043bae7193ae512e8e6e6cd666ef3ea46db6df63bd22f201c5fd682ea', 'utf-8'),
                    b'timestamp': b'1579716659',
                    b'page': b'next1'
                })
        data = response.json_value()
        self.assertFalse(data['success'])
