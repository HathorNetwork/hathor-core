# encoding: utf-8

from collections import namedtuple
import time

RateLimiterLimit = namedtuple('RateLimiterLimit', 'max_hits window_seconds')


class RateLimiter(object):
    """ Implement a multi-key rate limiter using the leaky bucket algorithm.
    """

    def __init__(self):
        self.keys = {}
        self.hits = {}

    def set_limit(self, key, max_hits, window_seconds):
        """ Set a limit to a given key, e.g., `max_hits = 10` and
        `window_seconds = 60` means at most 10 hits per minute.
        """
        assert(window_seconds > 0)
        self.keys[key] = RateLimiterLimit(max_hits, window_seconds)

    def get_limit(self, key):
        """ Get a limit to a given key.
        """
        return self.keys.get(key, None)

    def unset_limit(self, key):
        """ Unset a limit to a given key. Next calls to `add_hit` with that key
        will be ignored.
        """
        self.reset(key)
        self.keys.pop(key, None)

    def add_hit(self, key, weight=1):
        """ Add a hit to a given key. You can use `weight` to add more than one hit.
        Return `True` if threshold has not been reached, or `False` otherwise.
        """
        if key not in self.keys:
            return True
        (max_hits, window_seconds) = self.keys[key]

        if key not in self.hits:
            self.hits[key] = RateLimiterLimit(weight, time.time())
            return True

        hits, latest_time = self.hits[key]

        dt = time.time() - latest_time

        # rate = max_hits / window_seconds (hits per second)
        # x = dt * rate
        # leaked_hits = floor(x) (hits obtained after dt seconds)
        leaked_hits, remainder = divmod(dt * max_hits, window_seconds)

        # leaked_hits * window_seconds + remainder = dt * max_hits
        # dt - remainder / max_hits = leaked_hits / rate
        new_time = latest_time + dt - remainder / float(max_hits)

        # First, update the bucket subtracting the leakage amount.
        new_hits = hits - leaked_hits
        if new_hits < 0:
            new_hits = 0

        # Then, add the new hits and check if it overflows.
        new_hits += weight
        allowance = True
        if new_hits > max_hits:
            allowance = False
            new_hits = max_hits

        self.hits[key] = RateLimiterLimit(new_hits, new_time)
        return allowance

    def reset(self, key):
        """ Reset the hits of a given key.
        """
        self.hits.pop(key, None)
