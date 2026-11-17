"""TxSource registry — lets new transaction types (transparent now; token-creation,
nano, fee, shielded later) be added without touching the driver. Concrete sources
register themselves with @register_txtype("name")."""
from __future__ import annotations

from typing import Callable, TypeVar

TXTYPE_REGISTRY: dict[str, type] = {}

T = TypeVar("T")


def register_txtype(name: str) -> Callable[[type[T]], type[T]]:
    def deco(cls: type[T]) -> type[T]:
        if name in TXTYPE_REGISTRY:
            raise ValueError(f"tx type {name!r} already registered")
        cls.name = name  # type: ignore[attr-defined]
        TXTYPE_REGISTRY[name] = cls
        return cls
    return deco


def get_txtype(name: str) -> type:
    if name not in TXTYPE_REGISTRY:
        raise KeyError(f"unknown tx type {name!r}; registered: {list_txtypes()}")
    return TXTYPE_REGISTRY[name]


def list_txtypes() -> list[str]:
    return sorted(TXTYPE_REGISTRY)
