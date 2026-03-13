"""Tests for OpenAPI 3.1 specification generator."""
import unittest
from typing import ClassVar, Literal, Optional, Union

from pydantic import Field

from hathor.api.openapi.decorators import api_endpoint, clear_endpoint_registry
from hathor.api.openapi.generator import OpenAPIGenerator
from hathor.api.schemas import ErrorResponse, ResponseModel, SuccessResponse
from hathor.utils.api import QueryParams
from hathor.utils.pydantic import BaseModel


class TestOpenAPIGenerator(unittest.TestCase):
    def setUp(self) -> None:
        clear_endpoint_registry()

    def tearDown(self) -> None:
        clear_endpoint_registry()

    def test_single_response_model(self) -> None:
        """Single response model should produce a 200 entry."""
        class MyResponse(ResponseModel):
            value: str

        class _Dummy:
            @api_endpoint(
                path='/test',
                method='GET',
                operation_id='test_op',
                summary='Test',
                response_model=MyResponse,
            )
            def render_GET(self, request):
                pass

        gen = OpenAPIGenerator()
        spec = gen.generate()

        responses = spec['paths']['/test']['get']['responses']
        self.assertIn('200', responses)
        self.assertEqual(responses['200']['description'], 'Success')
        schema = responses['200']['content']['application/json']['schema']
        self.assertEqual(schema, {'$ref': '#/components/schemas/MyResponse'})

    def test_union_response_model(self) -> None:
        """Union response model should produce separate entries per status code."""
        class SuccessResp(ResponseModel):
            data: str

        class ErrorResp(ResponseModel):
            http_status_code: ClassVar[int] = 400
            error: str

        class _Dummy:
            @api_endpoint(
                path='/test',
                method='GET',
                operation_id='test_op',
                summary='Test',
                response_model=Union[SuccessResp, ErrorResp],
            )
            def render_GET(self, request):
                pass

        gen = OpenAPIGenerator()
        spec = gen.generate()

        responses = spec['paths']['/test']['get']['responses']
        self.assertIn('200', responses)
        self.assertIn('400', responses)
        self.assertEqual(
            responses['200']['content']['application/json']['schema'],
            {'$ref': '#/components/schemas/SuccessResp'},
        )
        self.assertEqual(
            responses['400']['content']['application/json']['schema'],
            {'$ref': '#/components/schemas/ErrorResp'},
        )

    def test_custom_status_code(self) -> None:
        """Custom http_status_code on model should produce the correct status code entry."""
        class HealthOk(ResponseModel):
            status: Literal['pass']

        class HealthFail(ResponseModel):
            http_status_code: ClassVar[int] = 503
            status: Literal['fail']

        class _Dummy:
            @api_endpoint(
                path='/health',
                method='GET',
                operation_id='health',
                summary='Health',
                response_model=Union[HealthOk, HealthFail],
            )
            def render_GET(self, request):
                pass

        gen = OpenAPIGenerator()
        spec = gen.generate()

        responses = spec['paths']['/health']['get']['responses']
        self.assertIn('200', responses)
        self.assertIn('503', responses)

    def test_multiple_models_same_status_code(self) -> None:
        """Multiple models with the same status code should use oneOf."""
        class Resp1(ResponseModel):
            kind: Literal['a']

        class Resp2(ResponseModel):
            kind: Literal['b']

        class _Dummy:
            @api_endpoint(
                path='/test',
                method='GET',
                operation_id='test_op',
                summary='Test',
                response_model=Union[Resp1, Resp2],
            )
            def render_GET(self, request):
                pass

        gen = OpenAPIGenerator()
        spec = gen.generate()

        responses = spec['paths']['/test']['get']['responses']
        schema = responses['200']['content']['application/json']['schema']
        self.assertIn('oneOf', schema)
        self.assertEqual(len(schema['oneOf']), 2)

    def test_duplicate_operation_detection(self) -> None:
        """Duplicate method+path in explicit registry should raise ValueError."""
        from hathor.api.openapi.decorators import EndpointMetadata

        metadata = EndpointMetadata(
            path='/test', method='GET', operation_id='test_op_1',
            summary='Test 1', description='', tags=[], visibility='public',
            rate_limit_global=[], rate_limit_per_ip=[],
            query_params_model=None, request_model=None,
            response_model=ResponseModel, deprecated=False,
            path_params_regex={}, path_params_descriptions={},
            catch_hathor_exceptions=True, max_body_size=1_000_000,
        )
        duplicate_registry = [metadata, metadata]

        gen = OpenAPIGenerator()
        with self.assertRaises(ValueError) as ctx:
            gen.generate(registry=duplicate_registry)
        self.assertIn('Duplicate operation', str(ctx.exception))

    def test_query_params(self) -> None:
        """query_params_model should produce correct parameters section."""
        class MyParams(QueryParams):
            page: int = Field(description="Page number")
            q: str | None = Field(default=None, description="Search query")

        class MyResponse(ResponseModel):
            items: list[str]

        class _Dummy:
            @api_endpoint(
                path='/search',
                method='GET',
                operation_id='search',
                summary='Search',
                query_params_model=MyParams,
                response_model=MyResponse,
            )
            def render_GET(self, request, *, params):
                pass

        gen = OpenAPIGenerator()
        spec = gen.generate()

        params = spec['paths']['/search']['get']['parameters']
        names = {p['name'] for p in params}
        self.assertIn('page', names)
        self.assertIn('q', names)

        page_param = next(p for p in params if p['name'] == 'page')
        self.assertTrue(page_param['required'])
        self.assertEqual(page_param['in'], 'query')

        q_param = next(p for p in params if p['name'] == 'q')
        self.assertFalse(q_param['required'])

    def test_path_params(self) -> None:
        """path_params_regex should produce correct path parameters."""
        class MyResponse(ResponseModel):
            value: str

        class _Dummy:
            @api_endpoint(
                path='/items/{item_id}',
                method='GET',
                operation_id='get_item',
                summary='Get item',
                response_model=MyResponse,
                path_params_regex={'item_id': '[a-f0-9]{64}'},
            )
            def render_GET(self, request):
                pass

        gen = OpenAPIGenerator()
        spec = gen.generate()

        params = spec['paths']['/items/{item_id}']['get']['parameters']
        self.assertEqual(len(params), 1)
        self.assertEqual(params[0]['name'], 'item_id')
        self.assertEqual(params[0]['in'], 'path')
        self.assertTrue(params[0]['required'])
        self.assertEqual(params[0]['schema']['pattern'], '[a-f0-9]{64}')

    def test_request_body(self) -> None:
        """request_model should produce correct requestBody section."""
        class MyRequest(BaseModel):
            name: str = Field(description="Item name")

        class MyResponse(ResponseModel):
            id: int

        class _Dummy:
            @api_endpoint(
                path='/items',
                method='POST',
                operation_id='create_item',
                summary='Create item',
                request_model=MyRequest,
                response_model=MyResponse,
            )
            def render_POST(self, request, *, body):
                pass

        gen = OpenAPIGenerator()
        spec = gen.generate()

        op = spec['paths']['/items']['post']
        self.assertIn('requestBody', op)
        self.assertTrue(op['requestBody']['required'])
        schema = op['requestBody']['content']['application/json']['schema']
        self.assertEqual(schema, {'$ref': '#/components/schemas/MyRequest'})

    def test_defs_hoisting(self) -> None:
        """Nested $defs should be hoisted to components/schemas with correct $ref."""
        class Inner(ResponseModel):
            name: str

        class Outer(ResponseModel):
            items: list[Inner]

        class _Dummy:
            @api_endpoint(
                path='/test',
                method='GET',
                operation_id='test_op',
                summary='Test',
                response_model=Outer,
            )
            def render_GET(self, request):
                pass

        gen = OpenAPIGenerator()
        spec = gen.generate()

        schemas = spec.get('components', {}).get('schemas', {})
        self.assertIn('Outer', schemas)
        self.assertIn('Inner', schemas)
        # $defs should have been removed from the Outer schema
        self.assertNotIn('$defs', schemas.get('Outer', {}))
        # $ref strings should correctly resolve to #/components/schemas/...
        items_schema = schemas['Outer']['properties']['items']['items']
        self.assertEqual(items_schema, {'$ref': '#/components/schemas/Inner'})

    def test_defs_hoisting_does_not_mutate_original(self) -> None:
        """Hoisting $defs should not mutate the original schema dict from model_json_schema()."""
        class InnerX(ResponseModel):
            name: str

        class OuterX(ResponseModel):
            items: list[InnerX]

        class _Dummy:
            @api_endpoint(
                path='/test',
                method='GET',
                operation_id='test_op',
                summary='Test',
                response_model=OuterX,
            )
            def render_GET(self, request):
                pass

        # Get original schema before generate
        original_schema = OuterX.model_json_schema(ref_template='#/components/schemas/{model}')
        had_defs = '$defs' in original_schema

        gen = OpenAPIGenerator()
        gen.generate()

        # Original schema from model_json_schema should not be mutated
        if had_defs:
            fresh_schema = OuterX.model_json_schema(ref_template='#/components/schemas/{model}')
            self.assertIn('$defs', fresh_schema)

    def test_multi_method_same_path(self) -> None:
        """Multiple methods on the same path should both appear with extensions."""
        class GetResp(ResponseModel):
            items: list[str]

        class PostResp(ResponseModel):
            id: int

        class _Dummy:
            @api_endpoint(
                path='/items',
                method='GET',
                operation_id='list_items',
                summary='List items',
                visibility='public',
                rate_limit_global=[{'rate': '10r/s', 'burst': 10, 'delay': 5}],
                response_model=GetResp,
            )
            def render_GET(self, request):
                pass

            @api_endpoint(
                path='/items',
                method='POST',
                operation_id='create_item',
                summary='Create item',
                visibility='private',
                response_model=PostResp,
            )
            def render_POST(self, request):
                pass

        gen = OpenAPIGenerator()
        spec = gen.generate()

        path_item = spec['paths']['/items']
        # Both methods should be present
        self.assertIn('get', path_item)
        self.assertIn('post', path_item)
        # Extensions should be at operation level, not path level
        self.assertEqual(path_item['get']['x-visibility'], 'public')
        self.assertEqual(path_item['post']['x-visibility'], 'private')
        # Rate limit only on GET
        self.assertIn('x-rate-limit', path_item['get'])
        self.assertNotIn('x-rate-limit', path_item['post'])

    def test_no_response_model(self) -> None:
        """No response_model should produce a simple 200 entry."""
        class _Dummy:
            @api_endpoint(
                path='/test',
                method='GET',
                operation_id='test_op',
                summary='Test',
            )
            def render_GET(self, request):
                pass

        gen = OpenAPIGenerator()
        spec = gen.generate()

        responses = spec['paths']['/test']['get']['responses']
        self.assertEqual(responses['200'], {'description': 'Success'})

    def test_error_response_base_class(self) -> None:
        """ErrorResponse base class should default to http_status_code=400."""
        class MySuccess(SuccessResponse):
            data: str

        class _Dummy:
            @api_endpoint(
                path='/test',
                method='GET',
                operation_id='test_op',
                summary='Test',
                response_model=Union[MySuccess, ErrorResponse],
            )
            def render_GET(self, request):
                pass

        gen = OpenAPIGenerator()
        spec = gen.generate()

        responses = spec['paths']['/test']['get']['responses']
        self.assertIn('200', responses)
        self.assertIn('400', responses)

    def test_optional_response_model_filters_nonetype(self) -> None:
        """CQ-004: Optional[SomeResponse] should filter out NoneType and not crash."""
        class SomeResponse(ResponseModel):
            value: str

        from hathor.api.openapi.decorators import EndpointMetadata

        metadata = EndpointMetadata(
            path='/test', method='GET', operation_id='test_optional',
            summary='Test', description='', tags=[], visibility='public',
            rate_limit_global=[], rate_limit_per_ip=[],
            query_params_model=None, request_model=None,
            response_model=Optional[SomeResponse], deprecated=False,
            path_params_regex={}, path_params_descriptions={},
            catch_hathor_exceptions=True, max_body_size=1_000_000,
        )

        gen = OpenAPIGenerator()
        spec = gen.generate(registry=[metadata])

        responses = spec['paths']['/test']['get']['responses']
        self.assertIn('200', responses)
        schema = responses['200']['content']['application/json']['schema']
        self.assertEqual(schema, {'$ref': '#/components/schemas/SomeResponse'})

    def test_non_basemodel_in_union_raises_typeerror(self) -> None:
        """CQ-004: Non-BaseModel type in Union response_model should raise TypeError."""
        from hathor.api.openapi.decorators import EndpointMetadata

        metadata = EndpointMetadata(
            path='/test', method='GET', operation_id='test_bad_union',
            summary='Test', description='', tags=[], visibility='public',
            rate_limit_global=[], rate_limit_per_ip=[],
            query_params_model=None, request_model=None,
            response_model=Union[ResponseModel, str], deprecated=False,
            path_params_regex={}, path_params_descriptions={},
            catch_hathor_exceptions=True, max_body_size=1_000_000,
        )

        gen = OpenAPIGenerator()
        with self.assertRaises(TypeError) as ctx:
            gen.generate(registry=[metadata])
        self.assertIn('non-BaseModel type', str(ctx.exception))

    def test_healthcheck_strict_fail_in_union(self) -> None:
        """AR-007: HealthcheckStrictFailResponse should appear in healthcheck spec."""
        class SuccessResp(ResponseModel):
            status: Literal['pass']

        class FailResp(ResponseModel):
            http_status_code: ClassVar[int] = 503
            status: Literal['fail']

        class StrictFailResp(ResponseModel):
            http_status_code: ClassVar[int] = 200
            status: Literal['fail']

        class _Dummy:
            @api_endpoint(
                path='/health',
                method='GET',
                operation_id='health_test',
                summary='Health',
                response_model=Union[SuccessResp, FailResp, StrictFailResp],
            )
            def render_GET(self, request):
                pass

        gen = OpenAPIGenerator()
        spec = gen.generate()

        responses = spec['paths']['/health']['get']['responses']
        self.assertIn('200', responses)
        self.assertIn('503', responses)
        # 200 should have oneOf with both SuccessResp and StrictFailResp
        schema_200 = responses['200']['content']['application/json']['schema']
        self.assertIn('oneOf', schema_200)
        self.assertEqual(len(schema_200['oneOf']), 2)

    def test_defs_collision_raises_error(self) -> None:
        """NEW: Conflicting $defs with same name should raise ValueError."""
        gen = OpenAPIGenerator()
        target: dict = {}
        schema_with_defs = {
            '$defs': {
                'Inner': {'type': 'object', 'properties': {'name': {'type': 'string'}}},
            },
        }
        gen._extract_defs(schema_with_defs, target)
        self.assertIn('Inner', target)

        # Now try to extract a conflicting $defs
        conflicting_schema = {
            '$defs': {
                'Inner': {'type': 'object', 'properties': {'value': {'type': 'integer'}}},
            },
        }
        with self.assertRaises(ValueError) as ctx:
            gen._extract_defs(conflicting_schema, target)
        self.assertIn('$defs collision', str(ctx.exception))

    def test_defs_same_schema_no_collision(self) -> None:
        """Identical $defs with same name should not raise."""
        gen = OpenAPIGenerator()
        target: dict = {}
        inner_schema = {'type': 'object', 'properties': {'name': {'type': 'string'}}}
        schema1 = {'$defs': {'Inner': dict(inner_schema)}}
        gen._extract_defs(schema1, target)

        schema2 = {'$defs': {'Inner': dict(inner_schema)}}
        # Should not raise since schemas are identical
        gen._extract_defs(schema2, target)
