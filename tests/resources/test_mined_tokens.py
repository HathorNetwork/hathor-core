from twisted.internet.defer import inlineCallbacks

from hathor.conf import HathorSettings
from hathor.mined_tokens import MinedTokensResource
from tests.resources.base_resource import StubSite, _BaseResourceTest
from tests.utils import add_new_blocks

settings = HathorSettings()


class MinedTokensTest(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp()
        self.web = StubSite(MinedTokensResource(self.manager))

    @inlineCallbacks
    def test_get(self):
        self.manager.wallet.unlock(b'MYPASS')

        response = yield self.web.get("mined_tokens")
        data = response.json_value()
        self.assertEqual(data['height'], 0)
        self.assertEqual(data['mined_tokens'], 0)

        add_new_blocks(self.manager, 5, advance_clock=1)

        response = yield self.web.get("mined_tokens")
        data = response.json_value()
        self.assertEqual(data['height'], 5)
        self.assertEqual(data['mined_tokens'], 5*settings.INITIAL_TOKENS_PER_BLOCK)

        add_new_blocks(self.manager, settings.BLOCKS_PER_HALVING + 15, advance_clock=1)
        mined_tokens = (settings.BLOCKS_PER_HALVING * settings.INITIAL_TOKENS_PER_BLOCK +
                        20 * settings.INITIAL_TOKENS_PER_BLOCK // 2)

        response = yield self.web.get("mined_tokens")
        data = response.json_value()
        self.assertEqual(data['height'], settings.BLOCKS_PER_HALVING + 20)
        self.assertEqual(data['mined_tokens'], mined_tokens)
