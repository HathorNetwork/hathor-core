from twisted.internet.defer import inlineCallbacks

from hathor.wallet.resources import LockWalletResource, StateWalletResource, UnlockWalletResource
from hathor_tests.resources.base_resource import StubSite, _BaseResourceTest


class LockTest(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp(unlock_wallet=False)
        self.web = StubSite(LockWalletResource(self.manager))
        self.web_unlock = StubSite(UnlockWalletResource(self.manager))
        self.web_state = StubSite(StateWalletResource(self.manager))

    @inlineCallbacks
    def test_locking(self):
        # Wallet is locked
        response = yield self.web_state.get('wallet/state')
        data = response.json_value()
        self.assertTrue(data['is_locked'])

        # Unlock it
        response_success = yield self.web_unlock.post('wallet/unlock', {'password': 'MYPASS'})
        data_success = response_success.json_value()
        self.assertTrue(data_success['success'])

        # Wallet is unlocked
        response_unlocked = yield self.web_state.get('wallet/state')
        data_unlocked = response_unlocked.json_value()
        self.assertFalse(data_unlocked['is_locked'])

        # Test locking the wallet with resource

        # Options
        yield self.web.options("wallet/lock")

        response_test = yield self.web.post('wallet/lock')
        data_test = response_test.json_value()
        self.assertTrue(data_test['success'])

        # Validate wallet is locked
        response_locked = yield self.web_state.get('wallet/state')
        data_locked = response_locked.json_value()
        self.assertTrue(data_locked['is_locked'])
