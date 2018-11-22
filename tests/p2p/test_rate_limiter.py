from twisted.internet.task import Clock
from hathor.p2p.rate_limiter import RateLimiter

from tests import unittest

import time


class RateLimiterTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()

        self.clock = Clock()
        self.clock.advance(time.time())

        self.rate_limiter = RateLimiter(reactor=self.clock)

    def test_limiter(self):
        key = 'test'
        self.rate_limiter.set_limit(key, 2, 2)

        # Hits limit
        self.assertTrue(self.rate_limiter.add_hit(key))
        self.assertTrue(self.rate_limiter.add_hit(key))
        self.assertFalse(self.rate_limiter.add_hit(key))

        # Advance 3 seconds to release limit
        self.clock.advance(3)

        # Add hits until limit again
        self.assertTrue(self.rate_limiter.add_hit(key))
        self.assertTrue(self.rate_limiter.add_hit(key))
        self.assertFalse(self.rate_limiter.add_hit(key))

        # Reset hits
        self.rate_limiter.reset(key)

        # Limit is free again
        self.assertTrue(self.rate_limiter.add_hit(key))

        # Get limit
        self.assertEqual(self.rate_limiter.get_limit(key).max_hits, 2)

        # Unset limit
        self.rate_limiter.unset_limit(key)
        self.assertIsNone(self.rate_limiter.get_limit(key))
