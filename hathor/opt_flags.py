#  Copyright 2026 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

"""Benchmark-only optimization gating (PR #1729 merge).

The TPS-benchmark harness exports ``HATHOR_OPT_<SECTION>`` env vars (``0`` = baseline,
``1``/unset = optimized) before building the node; the *appended* optimization sites in
hathor-core read them through :func:`opt_enabled`. The default is optimized (ON), so normal
production runs are unaffected when the env vars are absent.

Section keys mirror the measured pipeline stages: ``s1 s2 s3s4 s5 s6``. This is a deliberate,
documented deviation that exists only to let the benchmark A/B each optimization; see
``tps_benchmarking/discussions/optimization-analysis/``.

NOTE (future): the flags are coarse — one boolean per section. Per-optimization sub-flags
(e.g. ``HATHOR_OPT_MEM_TIPS``) are planned; until then a section flag toggles all of its
optimizations together.
"""
from __future__ import annotations

import os
from functools import lru_cache


@lru_cache(maxsize=None)
def opt_enabled(section: str) -> bool:
    """Return whether the optimized code path for ``section`` is enabled.

    True (default) unless the harness set ``HATHOR_OPT_<SECTION>=0``. Cached because the env is
    set once per run before any vertex is processed; the harness calls ``cache_clear()`` when it
    rebuilds (e.g. multiple harnesses in one process)."""
    return os.environ.get(f"HATHOR_OPT_{section.upper()}", "1") != "0"
