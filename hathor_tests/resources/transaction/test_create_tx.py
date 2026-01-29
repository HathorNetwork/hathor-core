import base64

from twisted.internet.defer import inlineCallbacks

from hathor.daa import TestMode
from hathor.simulator.utils import add_new_blocks
from hathor.transaction import Transaction
from hathor.transaction.resources import CreateTxResource
from hathor.transaction.scripts import create_base_script
from hathor_tests.resources.base_resource import StubSite, _BaseResourceTest
from hathor_tests.utils import add_blocks_unlock_reward, add_new_tx
from hathorlib.scripts import P2PKH


class TransactionTest(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp()
        self.web = StubSite(CreateTxResource(self.manager))
        self.manager.wallet.unlock(b'MYPASS')
        self.spent_blocks = add_new_blocks(self.manager, 10)
        self.unspent_blocks = add_blocks_unlock_reward(self.manager)
        add_blocks_unlock_reward(self.manager)
        self.unspent_address = self.manager.wallet.get_unused_address()
        self.unspent_tx = add_new_tx(self.manager, self.unspent_address, 100)
        self.unspent_tx2 = add_new_tx(self.manager, self.unspent_address, 200)
        self.unspent_tx3 = add_new_tx(self.manager, self.unspent_address, 300)
        add_blocks_unlock_reward(self.manager)

    # Example from the design:
    #
    # POST request body:
    #
    # {
    #   "inputs": [
    #     {
    #       "tx_id": "000005551d7740fd7d3c0acc50b5677fdd844f1225985aa431e1712af2a2fd89",
    #       "index": 1
    #     }
    #   ],
    #   "outputs": [
    #     {
    #       "address": "HNXsVtRUmwDCtpcCJUrH4QiHo9kUKx199A",
    #       "value": 5600
    #     }
    #   ]
    # }
    #
    # POST response body:
    #
    # {
    #   "success": true,
    #   "hex_data": "0001000101000005551d7740fd7d3c0acc50b5677fdd844f1225985aa431e171\
    # 2af2a2fd89010000000015e000001976a914afa600556bf43ece9b8e0486baa31\
    # bd46a82c3af88ac40310c373eed982e5f63d94d0200000000b0e8be665f308f1d\
    # 48d2201060846203280062b1cccc4e3d657486e90000000071c0d2cafa192b421\
    # bb5727c84174c999f9400d3be74331e7feba08a00000000",
    #   "data": {
    #     "timestamp": 1600379213,
    #     "version": 1,
    #     "weight": 17.047717984205683,
    #     "parents": [
    #       "00000000b0e8be665f308f1d48d2201060846203280062b1cccc4e3d657486e9",
    #       "0000000071c0d2cafa192b421bb5727c84174c999f9400d3be74331e7feba08a"
    #     ],
    #     "inputs": [
    #       {
    #         "tx_id": "000005551d7740fd7d3c0acc50b5677fdd844f1225985aa431e1712af2a2fd89",
    #         "index": 1,
    #         "data": ""
    #       }
    #     ],
    #     "outputs": [
    #       {
    #         "value": 5600,
    #         "token_data": 0,
    #         "script": "dqkUr6YAVWv0Ps6bjgSGuqMb1GqCw6+IrA=="
    #       }
    #     ],
    #     "tokens": []
    #   }
    # }

    @inlineCallbacks
    def test_spend_block(self):
        block = self.unspent_blocks[0]
        address = 'HNXsVtRUmwDCtpcCJUrH4QiHo9kUKx199A'
        script = create_base_script(address).get_script()
        resp = (yield self.web.post('create_tx', {
            'inputs': [
                {
                    'tx_id': block.hash_hex,
                    'index': 0,
                }
            ],
            'outputs': [
                {
                    'address': address,
                    'value': 6400,
                }
            ]
        })).json_value()
        self.assertEqual(resp['success'], True)
        data = resp['data']
        hex_data = resp['hex_data']
        struct_bytes = bytes.fromhex(hex_data)
        tx = Transaction.create_from_struct(struct_bytes)
        tx_data = tx.to_json()
        del tx_data['hash']
        del tx_data['nonce']
        self.assertEqual(data, tx_data)
        self.assertEqual(len(tx.inputs), 1)
        self.assertEqual(tx.inputs[0].tx_id, block.hash)
        self.assertEqual(tx.inputs[0].index, 0)
        self.assertEqual(tx.inputs[0].data, b'')
        self.assertEqual(len(tx.outputs), 1)
        self.assertEqual(tx.outputs[0].value, 6400)
        self.assertEqual(tx.outputs[0].token_data, 0)
        self.assertEqual(tx.outputs[0].script, script)

    @inlineCallbacks
    def test_spend_tx(self):
        src_tx = self.unspent_tx
        address = 'HNXsVtRUmwDCtpcCJUrH4QiHo9kUKx199A'
        script = create_base_script(address).get_script()
        resp = (yield self.web.post('create_tx', {
            'inputs': [
                {
                    'tx_id': src_tx.hash_hex,
                    'index': 1,
                }
            ],
            'outputs': [
                {
                    'address': address,
                    'value': 100,
                }
            ]
        })).json_value()
        self.assertEqual(resp['success'], True)
        data = resp['data']
        hex_data = resp['hex_data']
        struct_bytes = bytes.fromhex(hex_data)
        tx = Transaction.create_from_struct(struct_bytes)
        tx_data = tx.to_json()
        del tx_data['hash']
        del tx_data['nonce']
        self.assertEqual(data, tx_data)
        self.assertEqual(len(tx.inputs), 1)
        self.assertEqual(tx.inputs[0].tx_id, src_tx.hash)
        self.assertEqual(tx.inputs[0].index, 1)
        self.assertEqual(tx.inputs[0].data, b'')
        self.assertEqual(len(tx.outputs), 1)
        self.assertEqual(tx.outputs[0].value, 100)
        self.assertEqual(tx.outputs[0].token_data, 0)
        self.assertEqual(tx.outputs[0].script, script)

    @inlineCallbacks
    def test_spend_tx_by_script(self):
        src_tx = self.unspent_tx
        address = 'HNXsVtRUmwDCtpcCJUrH4QiHo9kUKx199A'
        script = create_base_script(address).get_script()
        script_str = base64.b64encode(script).decode('utf-8')
        resp = (yield self.web.post('create_tx', {
            'inputs': [
                {
                    'tx_id': src_tx.hash_hex,
                    'index': 1,
                }
            ],
            'outputs': [
                {
                    'script': script_str,
                    'value': 100,
                }
            ]
        })).json_value()
        self.assertEqual(resp['success'], True)
        data = resp['data']
        hex_data = resp['hex_data']
        struct_bytes = bytes.fromhex(hex_data)
        tx = Transaction.create_from_struct(struct_bytes)
        tx_data = tx.to_json()
        del tx_data['hash']
        del tx_data['nonce']
        self.assertEqual(data, tx_data)
        self.assertEqual(len(tx.inputs), 1)
        self.assertEqual(tx.inputs[0].tx_id, src_tx.hash)
        self.assertEqual(tx.inputs[0].index, 1)
        self.assertEqual(tx.inputs[0].data, b'')
        self.assertEqual(len(tx.outputs), 1)
        self.assertEqual(tx.outputs[0].value, 100)
        self.assertEqual(tx.outputs[0].token_data, 0)
        self.assertEqual(tx.outputs[0].script, script)

    @inlineCallbacks
    def test_tx_propagate(self):
        self.manager.daa.TEST_MODE = TestMode.DISABLED  # disable test_mode so the weight is not 1
        src_tx = self.unspent_tx
        output_address = 'HNXsVtRUmwDCtpcCJUrH4QiHo9kUKx199A'
        resp = (yield self.web.post('create_tx', {
            'inputs': [
                {
                    'tx_id': src_tx.hash_hex,
                    'index': 1,
                }
            ],
            'outputs': [
                {
                    'address': output_address,
                    'value': 100,
                }
            ]
        })).json_value()
        self.assertEqual(resp['success'], True)
        data = resp['data']
        hex_data = resp['hex_data']
        struct_bytes = bytes.fromhex(hex_data)
        orig_tx = Transaction.create_from_struct(struct_bytes)
        tx = orig_tx.clone()
        tx_data = tx.to_json()
        del tx_data['hash']
        del tx_data['nonce']
        self.assertEqual(data, tx_data)
        data_to_sign = tx.get_sighash_all()
        private_key = self.manager.wallet.get_private_key(self.unspent_address)
        public_key_bytes, signature_bytes = self.manager.wallet.get_input_aux_data(data_to_sign, private_key)
        input_data = P2PKH.create_input_data(public_key_bytes, signature_bytes)
        tx.inputs[0].data = input_data
        # XXX: tx.resolve is a bit CPU intensive, but not so much as to make this test disabled by default
        self.manager.cpu_mining_service.resolve(tx, update_time=False)
        self.assertTrue(self.manager.propagate_tx(tx))

    @inlineCallbacks
    def test_tx_propagate_multiple_inputs(self):
        self.manager.daa.TEST_MODE = TestMode.DISABLED  # disable test_mode so the weight is not 1
        output_address = 'HNXsVtRUmwDCtpcCJUrH4QiHo9kUKx199A'
        resp = (yield self.web.post('create_tx', {
            'inputs': [
                {
                    'tx_id': self.unspent_tx.hash_hex,
                    'index': 1,
                },
                {
                    'tx_id': self.unspent_tx2.hash_hex,
                    'index': 1,
                },
                {
                    'tx_id': self.unspent_tx3.hash_hex,
                    'index': 1,
                },
            ],
            'outputs': [
                {
                    'address': output_address,
                    'value': 600,
                },
            ]
        })).json_value()
        self.assertEqual(resp['success'], True)
        data = resp['data']
        hex_data = resp['hex_data']
        struct_bytes = bytes.fromhex(hex_data)
        orig_tx = Transaction.create_from_struct(struct_bytes)
        tx = orig_tx.clone()
        tx_data = tx.to_json()
        del tx_data['hash']
        del tx_data['nonce']
        self.assertEqual(data, tx_data)
        data_to_sign = tx.get_sighash_all()
        private_key = self.manager.wallet.get_private_key(self.unspent_address)
        public_key_bytes, signature_bytes = self.manager.wallet.get_input_aux_data(data_to_sign, private_key)
        input_data = P2PKH.create_input_data(public_key_bytes, signature_bytes)
        tx.inputs[0].data = input_data
        tx.inputs[1].data = input_data
        tx.inputs[2].data = input_data
        # XXX: tx.resolve is a bit CPU intensive, but not so much as to make this test disabled by default
        self.manager.cpu_mining_service.resolve(tx, update_time=False)
        self.assertTrue(self.manager.propagate_tx(tx))

    @inlineCallbacks
    def test_already_spent(self):
        block = self.spent_blocks[0]
        resp = (yield self.web.post('create_tx', {
            'inputs': [
                {
                    'tx_id': block.hash_hex,
                    'index': 0,
                }
            ],
            'outputs': [
                {
                    'address': 'HNXsVtRUmwDCtpcCJUrH4QiHo9kUKx199A',
                    'value': 6400,
                }
            ]
        })).json_value()
        self.assertEqual(resp, {
            'error': 'At least one of your inputs has already been spent.',
        })

    @inlineCallbacks
    def test_invalid_value(self):
        resp = (yield self.web.post('create_tx', {
            'inputs': [
                {
                    'tx_id': self.unspent_tx.hash_hex,
                    'index': 1,
                }
            ],
            'outputs': [
                {
                    'address': 'HNXsVtRUmwDCtpcCJUrH4QiHo9kUKx199A',
                    'value': 101,
                }
            ]
        })).json_value()
        self.assertEqual(resp, {
            'error': 'HTR balance is different than expected. (amount=1, expected=0)'
        })

    @inlineCallbacks
    def test_invalid_value2(self):
        resp = (yield self.web.post('create_tx', {
            'inputs': [
                {
                    'tx_id': self.unspent_tx.hash_hex,
                    'index': 1,
                }
            ],
            'outputs': [
                {
                    'address': 'HNXsVtRUmwDCtpcCJUrH4QiHo9kUKx199A',
                    'value': 99,
                }
            ]
        })).json_value()
        self.assertEqual(resp, {
            'error': 'HTR balance is different than expected. (amount=-1, expected=0)'
        })

    @inlineCallbacks
    def test_invalid_address(self):
        resp = (yield self.web.post('create_tx', {
            'inputs': [
                {
                    'tx_id': self.unspent_tx.hash_hex,
                    'index': 1,
                }
            ],
            'outputs': [
                {
                    'address': 'HNXsVtRUmwDCtpcCJUrH4QiHo9kUKx199Aa',
                    'value': 99,
                }
            ]
        })).json_value()
        self.assertEqual(resp, {
            'error': 'Address size must have 25 bytes'
        })

    # TODO: tests that use the tokens field (i.e. not only HTR)
