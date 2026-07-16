# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

"""Tests for API-version path prefixing."""

from hathor.api.openapi.versioning import deep_merge, path_version_prefix, prefix_unversioned_paths
from hathor.api_util import APIVersion


def _path_item(description: str = 'ok') -> dict:
    return {'post': {'responses': {'200': {'description': description}}}}


class TestPathVersionPrefix:
    def test_v1a_prefix(self) -> None:
        assert path_version_prefix('/v1a/create_tx') == APIVersion.V1A

    def test_v2_prefix(self) -> None:
        assert path_version_prefix('/v2/create_tx') == APIVersion.V2

    def test_nested_path_uses_first_segment(self) -> None:
        assert path_version_prefix('/v2/thin_wallet/token') == APIVersion.V2

    def test_unprefixed_path_returns_none(self) -> None:
        assert path_version_prefix('/status') is None

    def test_unknown_prefix_returns_none(self) -> None:
        assert path_version_prefix('/v3/create_tx') is None


class TestDeepMerge:
    def test_merges_nested_dicts_without_mutating(self) -> None:
        base = {'a': {'b': 1, 'c': 2}}
        override = {'a': {'c': 3, 'd': 4}}
        merged = deep_merge(base, override)
        assert merged == {'a': {'b': 1, 'c': 3, 'd': 4}}
        # base is untouched
        assert base == {'a': {'b': 1, 'c': 2}}

    def test_lists_are_replaced_not_concatenated(self) -> None:
        assert deep_merge({'a': [1, 2]}, {'a': [3]}) == {'a': [3]}


class TestPrefixUnversionedPaths:
    def test_unversioned_path_prefixed_with_default(self) -> None:
        out = prefix_unversioned_paths({'paths': {'/b': _path_item()}})
        assert sorted(out['paths']) == ['/v1a/b']

    def test_v1a_path_carried_through(self) -> None:
        out = prefix_unversioned_paths({'paths': {'/v1a/a': _path_item()}})
        assert sorted(out['paths']) == ['/v1a/a']

    def test_v2_path_carried_through(self) -> None:
        out = prefix_unversioned_paths({'paths': {'/v2/a': _path_item()}})
        assert sorted(out['paths']) == ['/v2/a']

    def test_mixed_paths(self) -> None:
        spec = {'paths': {'/status': _path_item(), '/v1a/a': _path_item(), '/v2/a': _path_item()}}
        out = prefix_unversioned_paths(spec)
        assert sorted(out['paths']) == ['/v1a/a', '/v1a/status', '/v2/a']

    def test_idempotent(self) -> None:
        spec = {'paths': {'/status': _path_item(), '/v2/a': _path_item()}}
        once = prefix_unversioned_paths(spec)
        twice = prefix_unversioned_paths(once)
        assert once['paths'] == twice['paths']

    def test_path_item_content_preserved(self) -> None:
        out = prefix_unversioned_paths({'paths': {'/status': _path_item('hello')}})
        assert out['paths']['/v1a/status']['post']['responses']['200']['description'] == 'hello'

    def test_prefixed_path_item_is_copied(self) -> None:
        item = _path_item()
        out = prefix_unversioned_paths({'paths': {'/status': item}})
        assert out['paths']['/v1a/status'] is not item

    def test_other_extensions_preserved(self) -> None:
        out = prefix_unversioned_paths({'paths': {'/a': {**_path_item(), 'x-visibility': 'public'}}})
        assert out['paths']['/v1a/a']['x-visibility'] == 'public'

    def test_components_and_info_carried_through(self) -> None:
        spec = {'info': {'title': 'X'}, 'components': {'schemas': {'S': {}}}, 'paths': {'/a': _path_item()}}
        out = prefix_unversioned_paths(spec)
        assert out['info'] == {'title': 'X'}
        assert out['components'] == {'schemas': {'S': {}}}
