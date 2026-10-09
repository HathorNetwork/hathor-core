"""The TxSource interface + the PreparedTx record.

A TxSource builds a batch of valid transactions for the node under test: it constructs
them, preloads any funding into the node (untimed setup), and returns the *target* txs
as PreparedTx. It must NOT drive the targets through the processing pipeline — that is
the driver's job (CP-4). This module imports nothing from hathor (so the registry and
`list` stay light); concrete sources do their hathor work lazily inside build().
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass
class PreparedTx:
    """A built, signed, PoW-resolved target transaction plus its serialized bytes.

    `raw` is kept alongside the object because S1 (deserialize) is timed by re-parsing
    these bytes in the driver loop."""
    tx: Any           # hathor Transaction (typed Any to avoid importing hathor here)
    raw: bytes
    n_inputs: int
    n_outputs: int


class TxSource(ABC):
    name: str  # set by @register_txtype

    @abstractmethod
    def build(
        self,
        harness: Any,
        num_txs: int,
        num_inputs: int,
        num_outputs: int,
    ) -> list[PreparedTx]:
        """Build `num_txs` independent txs (each with exactly num_inputs/num_outputs),
        preload their funding into `harness.manager`, and return them as PreparedTx —
        not yet driven through the pipeline."""
        raise NotImplementedError
