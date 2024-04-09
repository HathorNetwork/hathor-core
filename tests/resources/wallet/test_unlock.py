from twisted.internet.defer import inlineCallbacks

from hathor.wallet import HDWallet
from hathor.wallet.resources import LockWalletResource, StateWalletResource, UnlockWalletResource
from tests import unittest
from tests.resources.base_resource import StubSite, _BaseResourceTest


class BaseUnlockTest(_BaseResourceTest._ResourceTest):
    __test__ = False

    def setUp(self):
        super().setUp(unlock_wallet=False)
        self.web = StubSite(UnlockWalletResource(self.manager))
        self.web_lock = StubSite(LockWalletResource(self.manager))
        self.web_state = StubSite(StateWalletResource(self.manager))

    @inlineCallbacks
    def test_unlocking(self):
        # Wallet is locked
        response = yield self.web_state.get("wallet/state")
        data = response.json_value()
        self.assertTrue(data['is_locked'])

        # Try to unlock with wrong password

        # Options
        yield self.web.options("wallet/unlock")

        response_error = yield self.web.post("wallet/unlock", {'password': 'wrong_password'})
        data_error = response_error.json_value()
        self.assertFalse(data_error['success'])

        # Try to unlock with correct password
        response_success = yield self.web.post("wallet/unlock", {'password': 'MYPASS'})
        data_success = response_success.json_value()
        self.assertTrue(data_success['success'])

        # Wallet is unlocked
        response_unlocked = yield self.web_state.get("wallet/state")
        data_unlocked = response_unlocked.json_value()
        self.assertFalse(data_unlocked['is_locked'])

    @inlineCallbacks
    def test_unlocking_hd_wallet(self):
        self.manager.wallet = HDWallet(metadata_service=self.manager.metadata_service)
        self.manager.wallet._manually_initialize()
        self.manager.wallet.unlock(tx_storage=self.manager.tx_storage)

        # Wallet is not locked
        response = yield self.web_state.get("wallet/state")
        data = response.json_value()
        self.assertFalse(data['is_locked'])

        # Lock the wallet
        response_lock = yield self.web_lock.post("wallet/lock")
        data_lock = response_lock.json_value()
        self.assertTrue(data_lock['success'])

        # Wallet is locked
        response_locked = yield self.web_state.get("wallet/state")
        data_locked = response_locked.json_value()
        self.assertTrue(data_locked['is_locked'])

        # Unlock wallet invalid words
        response_invalid = yield self.web.post("wallet/unlock", {'words': 'abc def', 'passphrase': ''})
        data_invalid = response_invalid.json_value()
        self.assertFalse(data_invalid['success'])

        # Unlock wallet
        response_success = yield self.web.post("wallet/unlock", {'passphrase': ''})
        data_success = response_success.json_value()
        self.assertTrue(data_success['success'])

        # Wallet is unlocked
        response_unlocked = yield self.web_state.get("wallet/state")
        data_unlocked = response_unlocked.json_value()
        self.assertFalse(data_unlocked['is_locked'])

        # Lock the wallet and unlock with same words
        self.manager.wallet.lock()
        response_words = yield self.web.post("wallet/unlock", {'words': data_success['words'], 'passphrase': ''})
        data_words = response_words.json_value()
        self.assertTrue(data_words['success'])


class SyncV1UnlockTest(unittest.SyncV1Params, BaseUnlockTest):
    __test__ = True


class SyncV2UnlockTest(unittest.SyncV2Params, BaseUnlockTest):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeUnlockTest(unittest.SyncBridgeParams, SyncV2UnlockTest):
    pass
