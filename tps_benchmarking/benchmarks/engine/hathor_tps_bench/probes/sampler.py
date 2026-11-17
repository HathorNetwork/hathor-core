"""Background time-series sampler.

A daemon thread that reads /proc at a fixed interval, producing the Sample series used
for over-time / versus-N charts, and tracking RSS/FD peaks for the batch summary. It
only *reads* /proc, so it does no processing work — the measured pipeline stays
single-threaded (see RFC §"Note on threading")."""
from __future__ import annotations

import threading
import time

from hathor_tps_bench.metrics.model import Sample
from hathor_tps_bench.probes import procstats


class ProcSampler:
    def __init__(self, interval_s: float = 0.1) -> None:
        self.interval_s = interval_s
        self.samples: list[Sample] = []
        self.rss_peak: int = 0
        self.fd_peak: int = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._t0 = 0.0
        self._progress = 0

    def set_progress(self, n_done: int) -> None:
        """Record how many txs are done, so samples carry a tx-axis for vs-N charts."""
        self._progress = n_done

    def start(self) -> "ProcSampler":
        self._t0 = time.perf_counter()
        self._thread = threading.Thread(target=self._loop, name="proc-sampler", daemon=True)
        self._thread.start()
        return self

    def _loop(self) -> None:
        while not self._stop.is_set():
            rss = procstats.read_rss_bytes()
            fds = procstats.read_fd_count()
            io_r, io_w = procstats.read_io()
            self.rss_peak = max(self.rss_peak, rss)
            self.fd_peak = max(self.fd_peak, fds)
            self.samples.append(Sample(
                t_rel_s=time.perf_counter() - self._t0,
                tx_done=self._progress,
                rss_bytes=rss,
                num_fds=fds,
                io_read_bytes=io_r,
                io_write_bytes=io_w,
            ))
            self._stop.wait(self.interval_s)

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
