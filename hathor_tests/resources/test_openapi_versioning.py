"""Tests for version-prefixed OpenAPI path expansion."""
import unittest

from hathor.api.openapi.versioning import deep_merge, expand_openapi_versions, resolve_api_versions
from hathor.api_util import APIVersion


def _path_item(description: str = 'ok') -> dict:
    return {'post': {'responses': {'200': {'description': description}}}}


class TestResolveApiVersions(unittest.TestCase):
    def test_absent_declaration_defaults_to_v1a(self) -> None:
        self.assertEqual(resolve_api_versions('/x', _path_item()), [APIVersion.V1A])

    def test_path_level_declaration(self) -> None:
        item = {**_path_item(), 'x-api-versions': ['v1a', 'v2']}
        self.assertEqual(resolve_api_versions('/x', item), [APIVersion.V1A, APIVersion.V2])

    def test_operation_level_declaration(self) -> None:
        item = {'post': {'x-api-versions': ['v2'], 'responses': {}}}
        self.assertEqual(resolve_api_versions('/x', item), [APIVersion.V2])

    def test_conflicting_operation_level_raises(self) -> None:
        item = {
            'get': {'x-api-versions': ['v1a'], 'responses': {}},
            'post': {'x-api-versions': ['v1a', 'v2'], 'responses': {}},
        }
        with self.assertRaises(ValueError) as ctx:
            resolve_api_versions('/x', item)
        self.assertIn('conflicting x-api-versions', str(ctx.exception))

    def test_unknown_version_raises(self) -> None:
        item = {**_path_item(), 'x-api-versions': ['v1a', 'v3']}
        with self.assertRaises(ValueError) as ctx:
            resolve_api_versions('/x', item)
        self.assertIn('unknown API version `v3`', str(ctx.exception))

    def test_empty_list_raises(self) -> None:
        item = {**_path_item(), 'x-api-versions': []}
        with self.assertRaises(ValueError) as ctx:
            resolve_api_versions('/x', item)
        self.assertIn('non-empty list', str(ctx.exception))


class TestDeepMerge(unittest.TestCase):
    def test_merges_nested_dicts_without_mutating(self) -> None:
        base = {'a': {'b': 1, 'c': 2}}
        override = {'a': {'c': 3, 'd': 4}}
        merged = deep_merge(base, override)
        self.assertEqual(merged, {'a': {'b': 1, 'c': 3, 'd': 4}})
        # base is untouched
        self.assertEqual(base, {'a': {'b': 1, 'c': 2}})

    def test_lists_are_replaced_not_concatenated(self) -> None:
        self.assertEqual(deep_merge({'a': [1, 2]}, {'a': [3]}), {'a': [3]})


class TestExpandOpenapiVersions(unittest.TestCase):
    def test_default_path_emitted_under_v1a_only(self) -> None:
        spec = {'paths': {'/b': _path_item()}}
        out = expand_openapi_versions(spec)
        self.assertEqual(sorted(out['paths']), ['/v1a/b'])

    def test_both_versions_emitted(self) -> None:
        spec = {'paths': {'/a': {**_path_item(), 'x-api-versions': ['v1a', 'v2']}}}
        out = expand_openapi_versions(spec)
        self.assertEqual(sorted(out['paths']), ['/v1a/a', '/v2/a'])

    def test_v2_only(self) -> None:
        spec = {'paths': {'/a': {**_path_item(), 'x-api-versions': ['v2']}}}
        out = expand_openapi_versions(spec)
        self.assertEqual(sorted(out['paths']), ['/v2/a'])

    def test_override_applies_only_to_its_version(self) -> None:
        spec = {
            'paths': {
                '/a': {
                    **_path_item('base'),
                    'x-api-versions': ['v1a', 'v2'],
                    'x-api-version-overrides': {
                        'v2': [{'path': ['post', 'responses', '200', 'description'], 'value': 'v2 only'}],
                    },
                },
            },
        }
        out = expand_openapi_versions(spec)
        self.assertEqual(out['paths']['/v1a/a']['post']['responses']['200']['description'], 'base')
        self.assertEqual(out['paths']['/v2/a']['post']['responses']['200']['description'], 'v2 only')

    def test_override_replaces_a_specific_list_element(self) -> None:
        spec = {
            'paths': {
                '/a': {
                    'post': {'parameters': [{'name': 'first'}, {'name': 'second'}]},
                    'x-api-versions': ['v1a', 'v2'],
                    'x-api-version-overrides': {
                        'v2': [{'path': ['post', 'parameters', 1, 'name'], 'value': 'renamed'}],
                    },
                },
            },
        }
        out = expand_openapi_versions(spec)
        self.assertEqual([p['name'] for p in out['paths']['/v1a/a']['post']['parameters']], ['first', 'second'])
        self.assertEqual([p['name'] for p in out['paths']['/v2/a']['post']['parameters']], ['first', 'renamed'])

    def test_override_adds_a_new_dict_key(self) -> None:
        spec = {
            'paths': {
                '/a': {
                    'post': {'responses': {'200': {'description': 'ok'}}},
                    'x-api-versions': ['v1a', 'v2'],
                    'x-api-version-overrides': {
                        'v2': [{'path': ['post', 'deprecated'], 'value': True}],
                    },
                },
            },
        }
        out = expand_openapi_versions(spec)
        self.assertNotIn('deprecated', out['paths']['/v1a/a']['post'])
        self.assertIs(out['paths']['/v2/a']['post']['deprecated'], True)

    def test_control_extensions_are_stripped(self) -> None:
        spec = {
            'paths': {
                '/a': {
                    **_path_item(),
                    'x-api-versions': ['v1a', 'v2'],
                    'x-api-version-overrides': {'v2': [{'path': ['post', 'responses'], 'value': {}}]},
                },
            },
        }
        out = expand_openapi_versions(spec)
        for item in out['paths'].values():
            self.assertNotIn('x-api-versions', item)
            self.assertNotIn('x-api-version-overrides', item)

    def test_other_extensions_are_preserved(self) -> None:
        spec = {'paths': {'/a': {**_path_item(), 'x-visibility': 'public'}}}
        out = expand_openapi_versions(spec)
        self.assertEqual(out['paths']['/v1a/a']['x-visibility'], 'public')

    def test_components_and_info_carried_through(self) -> None:
        spec = {'info': {'title': 'X'}, 'components': {'schemas': {'S': {}}}, 'paths': {'/a': _path_item()}}
        out = expand_openapi_versions(spec)
        self.assertEqual(out['info'], {'title': 'X'})
        self.assertEqual(out['components'], {'schemas': {'S': {}}})

    def test_empty_override_is_a_noop(self) -> None:
        spec = {
            'paths': {
                '/a': {
                    **_path_item('base'),
                    'x-api-versions': ['v1a', 'v2'],
                    'x-api-version-overrides': {'v2': []},
                },
            },
        }
        out = expand_openapi_versions(spec)
        self.assertEqual(out['paths']['/v1a/a'], out['paths']['/v2/a'])
        self.assertEqual(out['paths']['/v2/a']['post']['responses']['200']['description'], 'base')

    def test_override_for_undeclared_version_raises(self) -> None:
        spec = {
            'paths': {
                '/a': {
                    **_path_item(),
                    'x-api-versions': ['v1a'],
                    'x-api-version-overrides': {'v2': [{'path': ['post'], 'value': {}}]},
                },
            },
        }
        with self.assertRaises(ValueError) as ctx:
            expand_openapi_versions(spec)
        self.assertIn('not in its served versions', str(ctx.exception))


class TestOverrideResolution(unittest.TestCase):
    def _expand_with_override(self, entry: object) -> dict:
        spec = {
            'paths': {
                '/a': {
                    'post': {'parameters': [{'name': 'first'}], 'responses': {'200': {'description': 'ok'}}},
                    'x-api-versions': ['v1a', 'v2'],
                    'x-api-version-overrides': {'v2': [entry]},
                },
            },
        }
        return expand_openapi_versions(spec)

    def test_unknown_key_raises(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            self._expand_with_override({'path': ['post', 'nope', 'x'], 'value': 1})
        self.assertIn("key 'nope' not found", str(ctx.exception))

    def test_index_out_of_range_raises(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            self._expand_with_override({'path': ['post', 'parameters', 5, 'name'], 'value': 'x'})
        self.assertIn('index 5 is out of range', str(ctx.exception))

    def test_int_segment_on_dict_raises(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            self._expand_with_override({'path': ['post', 0], 'value': 'x'})
        self.assertIn('int segment 0 expects a list', str(ctx.exception))

    def test_str_segment_on_list_raises(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            self._expand_with_override({'path': ['post', 'parameters', 'name'], 'value': 'x'})
        self.assertIn("str segment 'name' expects a dict", str(ctx.exception))

    def test_invalid_segment_type_raises(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            self._expand_with_override({'path': ['post', None], 'value': 'x'})
        self.assertIn('must be a str (dict key) or int (list index)', str(ctx.exception))

    def test_bool_segment_raises(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            self._expand_with_override({'path': ['post', True], 'value': 'x'})
        self.assertIn('must be a str (dict key) or int (list index)', str(ctx.exception))

    def test_malformed_entry_raises(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            self._expand_with_override({'path': ['post']})
        self.assertIn('malformed override entry', str(ctx.exception))

    def test_empty_path_raises(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            self._expand_with_override({'path': [], 'value': 'x'})
        self.assertIn('empty or non-list path', str(ctx.exception))
