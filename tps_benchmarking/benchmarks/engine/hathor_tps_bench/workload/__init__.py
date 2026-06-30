"""Workload sources. The `TxSource` interface + registry live here; concrete
sources (e.g. the transparent DAGBuilder source) are added in CP-3."""
from hathor_tps_bench.workload.registry import (
    TXTYPE_REGISTRY,
    get_txtype,
    list_txtypes,
    register_txtype,
)

# Import concrete sources so they self-register. This stays hathor-free: the modules
# do their hathor work lazily inside build(), so `list`/`validate` remain light.
from hathor_tps_bench.workload import transparent  # noqa: F401,E402  (registers "transparent")

__all__ = ["TXTYPE_REGISTRY", "register_txtype", "get_txtype", "list_txtypes"]
