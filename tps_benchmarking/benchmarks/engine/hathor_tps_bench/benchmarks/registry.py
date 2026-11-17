"""Benchmark registry. Each benchmark declares a selector `name` and the results
sub-folder it writes to. The runner (CP-5) discovers benchmarks via this registry;
`--select` chooses a subset."""
from __future__ import annotations

from typing import Callable, NamedTuple, TypeVar


class BenchmarkEntry(NamedTuple):
    cls: type
    output_folder: str


BENCHMARK_REGISTRY: dict[str, BenchmarkEntry] = {}

T = TypeVar("T")


def register_benchmark(name: str, output_folder: str) -> Callable[[type[T]], type[T]]:
    def deco(cls: type[T]) -> type[T]:
        if name in BENCHMARK_REGISTRY:
            raise ValueError(f"benchmark {name!r} already registered")
        cls.name = name              # type: ignore[attr-defined]
        cls.output_folder = output_folder  # type: ignore[attr-defined]
        BENCHMARK_REGISTRY[name] = BenchmarkEntry(cls, output_folder)
        return cls
    return deco


def get_benchmark(name: str) -> BenchmarkEntry:
    if name not in BENCHMARK_REGISTRY:
        raise KeyError(f"unknown benchmark {name!r}; registered: {list_benchmarks()}")
    return BENCHMARK_REGISTRY[name]


def list_benchmarks() -> list[str]:
    return sorted(BENCHMARK_REGISTRY)
