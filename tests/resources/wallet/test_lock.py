from hathor.wallet.resources import LockWalletResource, StateWalletResource, UnlockWalletResource
from twisted.internet.defer import inlineCallbacks
from tests.resources.base_resource import TestSite, _BaseResourceTest


class LockTest(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp()
        self.web = TestSite(LockWalletResource(self.manager))
        self.web_unlock = TestSite(UnlockWalletResource(self.manager))
        self.web_state = TestSite(StateWalletResource(self.manager))

    @inlineCallbacks
    def test_locking(self):
        # Wallet is locked
        response = yield self.web_state.get('wallet/state')
        data = response.json_value()
        self.assertTrue(data['is_locked'])

        # Unlock it
        response_success = yield self.web_unlock.post('wallet/unlock', {b'password': b'MYPASS'})
        data_success = response_success.json_value()
        self.assertTrue(data_success['success'])

        # Wallet is unlocked
        response_unlocked = yield self.web_state.get('wallet/state')
        data_unlocked = response_unlocked.json_value()
        self.assertFalse(data_unlocked['is_locked'])

        # Test locking the wallet with resource
        response_test = yield self.web.post('wallet/lock')
        data_test = response_test.json_value()
        self.assertTrue(data_test['success'])

        # Validate wallet is locked
        response_locked = yield self.web_state.get('wallet/state')
        data_locked = response_locked.json_value()
        self.assertTrue(data_locked['is_locked'])
