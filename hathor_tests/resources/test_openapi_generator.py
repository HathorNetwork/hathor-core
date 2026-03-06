"""Tests for OpenAPI 3.1 specification generator."""
import unittest
from typing import ClassVar, Literal, Union

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
        """Duplicate method+path should raise ValueError."""
        class MyResponse(ResponseModel):
            value: str

        class _Dummy1:
            @api_endpoint(
                path='/test',
                method='GET',
                operation_id='test_op_1',
                summary='Test 1',
                response_model=MyResponse,
            )
            def render_GET(self, request):
                pass

        class _Dummy2:
            @api_endpoint(
                path='/test',
                method='GET',
                operation_id='test_op_2',
                summary='Test 2',
                response_model=MyResponse,
            )
            def render_GET(self, request):
                pass

        gen = OpenAPIGenerator()
        with self.assertRaises(ValueError) as ctx:
            gen.generate()
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
