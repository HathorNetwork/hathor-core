from collections import defaultdict
from typing import TYPE_CHECKING, Dict, Optional, Tuple

from twisted.internet import reactor as default_reactor
from twisted.internet.interfaces import IReactorCore
from twisted.logger import Logger, LogLevel

from hathor.p2p.rate_limiter import RateLimiter

if TYPE_CHECKING:
    from hathor.manager import HathorManager  # noqa: F401


class RateLimitedLogger(Logger):
    def __init__(self, namespace=None, source=None, observer=None, reactor: IReactorCore = None):
        super().__init__()
        print(self.observer)

        if reactor is None:
            self.reactor = default_reactor
        else:
            self.reactor = reactor

        self.rate_limiter = RateLimiter()
        self.suppression_message: Dict[str, str] = {}

        self.counters: Dict[str, int] = defaultdict(int)
        self.latest_log: Dict[str, float] = defaultdict(int)

        # Delay between message suppression logs.
        self.suppression_log_delay: int = 5

        # Last delayed call.
        self.delayed_call = None

    def set_limit(self, key: str, max_hits: int, window_seconds: int, suppression_message: str) -> None:
        self.rate_limiter.set_limit(key, max_hits, window_seconds)
        self.suppression_message[key] = suppression_message

    def emit(self, level: LogLevel, fmt: Optional[str] = None, **kwargs):
        if not fmt:
            super().emit(level, fmt, **kwargs)

        key = (level, fmt)

        if self.rate_limiter.add_hit(key):
            if self.delayed_call and self.delayed_call.active:
                self.delayed_call.cancel()
                self.do_suppression_log(key)
            super().emit(level, fmt, **kwargs)
        else:
            if self.counters[key] == 0:
                self.schedule_suppression_log(key)
            self.counters[key] += 1

    def schedule_suppression_log(self, key: Tuple[LogLevel, str]) -> None:
        if self.delayed_call and self.delayed_call.active:
            return
        self.latest_log[key] = self.reactor.seconds()
        self.delayed_call = self.reactor.callLater(self.suppression_log_delay, self.do_suppression_log, key)

    def do_suppression_log(self, key: Tuple[LogLevel, str]) -> None:
        counter = self.counters[key]
        msg = self.suppression_message[key]
        now = self.reactor.seconds()
        dt = now - self.latest_log[key]

        level, fmt = key
        super().emit(level, fmt, counter=counter, dt=dt)

        self.counters[key] = 0
