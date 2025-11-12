from hathor.p2p.rate_limiter import RateLimiter
from hathor.util import not_none
from hathor_tests import unittest


class RateLimiterTestCase(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.rate_limiter = RateLimiter(reactor=self.clock)

    def test_limiter(self) -> None:
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
        self.assertEqual(not_none(self.rate_limiter.get_limit(key)).max_hits, 2)

        # Unset limit
        self.rate_limiter.unset_limit(key)
        self.assertIsNone(self.rate_limiter.get_limit(key))
