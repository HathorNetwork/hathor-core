# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

"""Normalize an OpenAPI spec so every path carries an API-version prefix.

Version-capable resources declare their paths already prefixed with the version they serve
(`/v1a/create_tx`, `/v2/create_tx`), one entry per version. Resources that are served under a single
version declare an unprefixed path (`/status`); those are emitted under the default version. Both the
docs generator and the nginx generator consume the normalized spec, so the version a path is served
under is read from its prefix in a single place.

`deep_merge()` is a small structural helper used when two path items for the same path are combined.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from hathor.api_util import DEFAULT_API_VERSIONS, APIVersion

_KNOWN_VERSION_PREFIXES = frozenset(version.value for version in APIVersion)


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge `override` onto `base`, returning a new dict without mutating either.

    Nested dicts are merged key by key; every other value (including lists) is replaced wholesale.
    """
    merged = deepcopy(base)
    for key, override_value in override.items():
        base_value = merged.get(key)
        if isinstance(base_value, dict) and isinstance(override_value, dict):
            merged[key] = deep_merge(base_value, override_value)
        else:
            merged[key] = deepcopy(override_value)
    return merged


def path_version_prefix(path: str) -> APIVersion | None:
    """Return the API version a path is already prefixed with, or `None` when it carries no prefix."""
    first_segment = path.strip('/').split('/', 1)[0]
    if first_segment in _KNOWN_VERSION_PREFIXES:
        return APIVersion(first_segment)
    return None


def prefix_unversioned_paths(openapi: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of `openapi` in which every path carries an API-version prefix.

    Paths that already begin with a known version segment are carried through unchanged; every other
    path is emitted once per default version, prefixed with it. Idempotent: re-applying it to an
    already-prefixed spec yields an equivalent spec. The rest of the document (components, info,
    servers) is carried through unchanged.
    """
    new_paths: dict[str, Any] = {}
    for path, path_item in openapi.get('paths', {}).items():
        if path_version_prefix(path) is not None:
            new_paths[path] = path_item
            continue
        for version in DEFAULT_API_VERSIONS:
            new_paths[f'/{version.value}{path}'] = deepcopy(path_item)
    return {**openapi, 'paths': new_paths}
