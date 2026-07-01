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

"""Expand an OpenAPI spec keyed by unversioned paths into one keyed by version-prefixed paths.

The merged spec produced by `get_openapi_dict()` keys every operation by its unversioned path
(e.g. `/create_tx`) and is the source of truth consumed by both the nginx generator and the docs.
For the published docs, this module rewrites that spec so each path is emitted once per API version
it is served under, prefixed accordingly (`/v1a/create_tx`, `/v2/create_tx`).

Two declarations drive the rewrite, both read from the unversioned spec:

- `x-api-versions`: the list of versions a path is served under. Absent → `DEFAULT_API_VERSIONS`.
- `x-api-version-overrides`: an optional `{version: [override, ...]}` map. Each override is a
  `{'path': [...], 'value': ...}` pair that resolves a location inside the base path item — `str`
  segments index dict keys, `int` segments index list elements — and replaces the value found there
  with `value` when emitting that version. This points at the single element that changes, so a
  version can document a different request/response schema (down to one list element) without
  restating its surrounding structure. Versions without overrides reuse the base item unchanged.
"""

from __future__ import annotations

import json
from copy import deepcopy
from typing import Any

from hathor.api_util import DEFAULT_API_VERSIONS, APIVersion

API_VERSIONS_EXTENSION = 'x-api-versions'
API_VERSION_OVERRIDES_EXTENSION = 'x-api-version-overrides'

# OpenAPI operation keys that may appear inside a path item.
_HTTP_METHODS = ('get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'trace')


def _parse_api_version(path: str, value: Any) -> APIVersion:
    """Parse a single version identifier, raising with path context on an unknown value."""
    try:
        return APIVersion(value)
    except ValueError:
        valid = ', '.join(version.value for version in APIVersion)
        raise ValueError(
            f'Path `{path}` references unknown API version `{value}`; valid values: {valid}'
        )


def resolve_api_versions(
    path: str,
    path_item: dict[str, Any],
    *,
    methods: list[str] | None = None,
) -> list[APIVersion]:
    """Resolve the API versions a path is served under from its `x-api-versions` declaration.

    This is the single source of truth shared by the docs expander and the nginx generator. The
    declaration may sit at the path-item level or, for specs generated per operation, on the
    operations themselves. Operation-level declarations must agree, since the path is served as a
    whole. When no declaration is present the path is served under `DEFAULT_API_VERSIONS`.

    `methods` restricts which operations are considered at the operation level. The nginx generator
    passes its public methods, since private methods do not participate in the emitted location.
    """
    raw = path_item.get(API_VERSIONS_EXTENSION)
    if raw is None:
        raw = _resolve_operation_level_versions(path, path_item, methods=methods)
    if raw is None:
        return list(DEFAULT_API_VERSIONS)
    if not isinstance(raw, list) or not raw:
        raise ValueError(f'Path `{path}` has invalid {API_VERSIONS_EXTENSION}, expected a non-empty list: {raw!r}')
    return [_parse_api_version(path, value) for value in raw]


def _resolve_operation_level_versions(
    path: str,
    path_item: dict[str, Any],
    *,
    methods: list[str] | None = None,
) -> Any:
    """Collapse operation-level `x-api-versions` to a single value, erroring when they disagree."""
    candidate_methods = _HTTP_METHODS if methods is None else methods
    values_by_method: dict[str, Any] = {}
    for method in candidate_methods:
        operation = path_item.get(method)
        if isinstance(operation, dict) and API_VERSIONS_EXTENSION in operation:
            values_by_method[method] = operation[API_VERSIONS_EXTENSION]

    if not values_by_method:
        return None

    distinct = {json.dumps(value, sort_keys=True) for value in values_by_method.values()}
    if len(distinct) > 1:
        methods_str = ', '.join(sorted(values_by_method))
        raise ValueError(
            f'Path `{path}` has conflicting {API_VERSIONS_EXTENSION} values across methods: {methods_str}'
        )

    return next(iter(values_by_method.values()))


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


def merge_path_items(base: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """Merge two path items for the same path (e.g. a GET and a POST sharing a URL).

    Operations and other extensions are deep-merged; `x-api-version-overrides` entries are
    concatenated per version, since each method contributes overrides scoped to its own operation
    and both must survive the merge.
    """
    merged = deep_merge(base, new)
    base_overrides = base.get(API_VERSION_OVERRIDES_EXTENSION)
    new_overrides = new.get(API_VERSION_OVERRIDES_EXTENSION)
    if base_overrides and new_overrides:
        concatenated = {version: list(entries) for version, entries in base_overrides.items()}
        for version, entries in new_overrides.items():
            concatenated.setdefault(version, []).extend(entries)
        merged[API_VERSION_OVERRIDES_EXTENSION] = concatenated
    return merged


def expand_openapi_versions(openapi: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of `openapi` whose paths are expanded to one version-prefixed entry per version.

    Each unversioned path is emitted under every version it declares; the version-control extensions
    are consumed here and dropped from the emitted items. The rest of the document (components, info,
    servers) is carried through unchanged.
    """
    new_paths: dict[str, Any] = {}
    for path, path_item in openapi.get('paths', {}).items():
        versions = resolve_api_versions(path, path_item)
        overrides = path_item.get(API_VERSION_OVERRIDES_EXTENSION, {})
        _validate_overrides(path, overrides, versions)

        base_item = {
            key: value
            for key, value in path_item.items()
            if key not in (API_VERSIONS_EXTENSION, API_VERSION_OVERRIDES_EXTENSION)
        }

        for version in versions:
            item = deepcopy(base_item)
            for entry in overrides.get(version.value, []):
                _apply_override(path, item, entry)
            new_paths[f'/{version.value}{path}'] = item

    return {**openapi, 'paths': new_paths}


def _validate_overrides(path: str, overrides: dict[str, Any], versions: list[APIVersion]) -> None:
    """Reject override entries that name an unknown version or one the path does not serve."""
    declared = {version.value for version in versions}
    for version_key in overrides:
        parsed = _parse_api_version(path, version_key)
        if parsed.value not in declared:
            served = ', '.join(sorted(declared))
            raise ValueError(
                f'Path `{path}` has an {API_VERSION_OVERRIDES_EXTENSION} for `{version_key}`, '
                f'which is not in its served versions: {served}'
            )


def _apply_override(path: str, item: dict[str, Any], entry: Any) -> None:
    """Resolve one override's `path` within `item` and replace the value found there with its `value`.

    The override path is a list of segments addressing the element to replace: `str` segments index
    dict keys, `int` segments index list elements. Intermediate segments must resolve to an existing
    element (a missing key or out-of-range index raises); the final segment may name a new dict key
    to add a field, but a list index must already exist, since lists are replaced element-wise here.
    """
    if not isinstance(entry, dict) or entry.keys() != {'path', 'value'}:
        raise ValueError(f'Path `{path}` has a malformed override entry, expected {{path, value}}: {entry!r}')
    segments = entry['path']
    if not isinstance(segments, list) or not segments:
        raise ValueError(f'Path `{path}` has an override with an empty or non-list path: {segments!r}')

    *parents, leaf = segments
    target = item
    for segment in parents:
        _check_segment(path, segments, target, segment, require_present=True)
        target = target[segment]
    _check_segment(path, segments, target, leaf, require_present=False)
    target[leaf] = entry['value']


def _check_segment(
    path: str,
    override_path: list[Any],
    container: Any,
    segment: Any,
    *,
    require_present: bool,
) -> None:
    """Validate that `segment` addresses an element of `container`, raising with full context if not.

    `require_present` is set for intermediate segments (which must already resolve) and unset for the
    final segment. A `str` segment requires a dict; an `int` segment requires a list and must be in
    range, since list elements can only be replaced, never appended.
    """
    if isinstance(segment, bool) or not isinstance(segment, (int, str)):
        raise ValueError(
            f'Path `{path}` override {override_path!r}: segment {segment!r} must be a str (dict key) '
            f'or int (list index)'
        )
    if isinstance(segment, int):
        if not isinstance(container, list):
            raise ValueError(
                f'Path `{path}` override {override_path!r}: int segment {segment} expects a list '
                f'but found {type(container).__name__}'
            )
        if not -len(container) <= segment < len(container):
            raise ValueError(
                f'Path `{path}` override {override_path!r}: index {segment} is out of range for a list '
                f'of length {len(container)}'
            )
        return
    if not isinstance(container, dict):
        raise ValueError(
            f'Path `{path}` override {override_path!r}: str segment {segment!r} expects a dict '
            f'but found {type(container).__name__}'
        )
    if require_present and segment not in container:
        raise ValueError(f'Path `{path}` override {override_path!r}: key {segment!r} not found in path item')
