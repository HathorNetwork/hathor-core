# encoding: utf-8

from collections import namedtuple

RateLimiterLimit = namedtuple('RateLimiterLimit', 'max_hits window_seconds')


class RateLimiter(object):
    """ Implement a multi-key rate limiter using the leaky bucket algorithm.
    """

    def __init__(self, reactor=None):
        # Stores the keys that are being limited and it's RateLimit
        # Dict[string, RateLimiterLimit]
        self.keys = {}

        # Stores the last hit for each key
        # Dict[string, RateLimiterLimit]
        self.hits = {}

        # :py:class:`twisted.internet.Reactor`
        if reactor is None:
            from twisted.internet import reactor
        self.reactor = reactor

    def set_limit(self, key, max_hits, window_seconds):
        """ Set a limit to a given key, e.g., `max_hits = 10` and
        `window_seconds = 60` means at most 10 hits per minute.

        :param key: Name of key to set the rate limit
        :type key: string

        :param max_hits: Maximum hits allowed for this key before the limit
        :type max_hits: int

        :param window_seconds: The maximum hits can be done in window_seconds
        :type window_seconds: int
        """
        assert(window_seconds > 0)
        self.keys[key] = RateLimiterLimit(max_hits, window_seconds)

    def get_limit(self, key):
        """ Get a limit to a given key.

        :type key: string
        """
        return self.keys.get(key, None)

    def unset_limit(self, key):
        """ Unset a limit to a given key. Next calls to `add_hit` with that key
        will be ignored.

        :type key: string
        """
        self.reset(key)
        self.keys.pop(key, None)

    def add_hit(self, key, weight=1):
        """ Add a hit to a given key. You can use `weight` to add more than one hit.
        Return `True` if threshold has not been reached, or `False` otherwise.

        :type key: string

        :param weight: How many hits this 'hit' means
        :type weight: int
        """
        if key not in self.keys:
            return True
        (max_hits, window_seconds) = self.keys[key]

        if key not in self.hits:
            self.hits[key] = RateLimiterLimit(weight, self.reactor.seconds())
            return True

        hits, latest_time = self.hits[key]

        dt = self.reactor.seconds() - latest_time

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

            :type key: string
        """
        self.hits.pop(key, None)
