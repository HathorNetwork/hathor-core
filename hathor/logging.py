from collections import defaultdict
from typing import Dict

from hathor.p2p.rate_limiter import RateLimiter


class LogRateLimiter(RateLimiter):
    def __init__(self, manager):
        self.manager = manager

        self.rate_limiter = RateLimiter()
        self.suppression_message: Dict[str, str] = {}

        self.counters: Dict[str, int] = defaultdict(int)
        self.latest_log: Dict[str, int] = defaultdict(int)

        # Delay between message suppression logs.
        self.suppression_log_delay: int = 5

        # Last delayed call.
        self.delayed_call = None

    def set_limit(self, key: str, max_hits: int, window_seconds: int, suppression_message: str) -> None:
        self.rate_limiter.set_limit(key, max_hits, window_seconds)
        self.suppression_message[key] = suppression_message

    def info(self, key: str, *args, **kwargs):
        if self.rate_limiter.add_hit(key):
            if self.counters[key] > 0:
                self.do_suppression_log()
            self.manager.log.info(*args, **kwargs)
        else:
            if self.counters[key] == 0:
                self.schedule_suppression_log()
            self.counters[key] += 1

    def schedule_suppression_log(self):
        if self.delayed_call and self.delayed_call.active:
            return
        self.delayed_call = self.manager.reactor.callLater(self.suppression_log_delay, self.do_suppression_log)

    def get_seconds(self):
        return self.manager.reactor.seconds()

    def do_suppression_log(self, key: str):
        counter = self.counters[key]
        msg = self.suppression_message[key]
        now = self.get_seconds()
        dt = now - self.latest_log[key]

        self.log.info(msg, counter=counter, dt=dt)

        self.counters[key] = 0
        self.latest_log[key] = now
