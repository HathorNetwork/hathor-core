"""Tests for the @api_endpoint decorator auto-validation and auto-serialization."""
import json
import unittest
from io import BytesIO
from typing import ClassVar
from unittest.mock import MagicMock

from pydantic import Field
from twisted.internet.defer import fail, succeed
from twisted.web.resource import Resource
from twisted.web.server import NOT_DONE_YET

from hathor.api.openapi.decorators import api_endpoint, clear_endpoint_registry
from hathor.api.schemas import ResponseModel
from hathor.utils.api import QueryParams


class _FakeRequest:
    """Minimal fake request for testing the decorator."""

    def __init__(self, args: dict | None = None, body: dict | None = None, headers: dict | None = None) -> None:
        self.args = args or {}
        self.responseCode = 200
        self.written: list[bytes] = []
        self._headers: dict[bytes, bytes] = {}
        self.requestHeaders = MagicMock()
        self.requestHeaders.getRawHeaders = MagicMock(return_value=None)
        self.finished = False

        if body is not None:
            self.content = BytesIO(json.dumps(body).encode())
        else:
            self.content = BytesIO(b'')

    def setResponseCode(self, code: int) -> None:
        self.responseCode = code

    def setHeader(self, name: bytes, value: bytes) -> None:
        self._headers[name] = value

    def write(self, data: bytes) -> None:
        self.written.append(data)

    def finish(self) -> None:
        self.finished = True

    def json_value(self) -> dict:
        return json.loads(b''.join(self.written))


class TestAutoValidationSuccess(unittest.TestCase):
    def setUp(self) -> None:
        clear_endpoint_registry()

    def tearDown(self) -> None:
        clear_endpoint_registry()

    def test_params_passed_as_kwarg(self) -> None:
        """Auto-validated query params should be passed as params= kwarg."""
        class MyParams(QueryParams):
            page: int = Field(description="Page number")

        class MyResponse(ResponseModel):
            page: int

        received_params = []

        class MyResource(Resource):
            @api_endpoint(
                path='/test',
                method='GET',
                operation_id='test',
                summary='Test',
                query_params_model=MyParams,
                response_model=MyResponse,
            )
            def render_GET(self, request, *, params):
                received_params.append(params)
                return MyResponse(page=params.page)

        request = _FakeRequest(args={b'page': [b'5']})
        resource = MyResource()
        result = resource.render_GET(request)  # type: ignore[call-arg]

        self.assertEqual(len(received_params), 1)
        self.assertEqual(received_params[0].page, 5)
        self.assertIsInstance(result, bytes)
        data = json.loads(result)
        self.assertEqual(data['page'], 5)


class TestAutoValidationFailure(unittest.TestCase):
    def setUp(self) -> None:
        clear_endpoint_registry()

    def tearDown(self) -> None:
        clear_endpoint_registry()

    def test_invalid_params_returns_400(self) -> None:
        """Invalid query params should return 400 error."""
        class MyParams(QueryParams):
            page: int = Field(description="Page number")

        class MyResponse(ResponseModel):
            page: int

        class MyResource(Resource):
            @api_endpoint(
                path='/test',
                method='GET',
                operation_id='test',
                summary='Test',
                query_params_model=MyParams,
                response_model=MyResponse,
            )
            def render_GET(self, request, *, params):
                return MyResponse(page=params.page)

        request = _FakeRequest(args={b'page': [b'not_a_number']})
        resource = MyResource()
        result = resource.render_GET(request)  # type: ignore[call-arg]

        self.assertEqual(request.responseCode, 400)
        data = json.loads(result)
        self.assertFalse(data['success'])
        self.assertIn('error', data)

    def test_missing_required_params_returns_400(self) -> None:
        """Missing required query params should return 400 error."""
        class MyParams(QueryParams):
            page: int = Field(description="Page number")

        class MyResponse(ResponseModel):
            page: int

        class MyResource(Resource):
            @api_endpoint(
                path='/test',
                method='GET',
                operation_id='test2',
                summary='Test',
                query_params_model=MyParams,
                response_model=MyResponse,
            )
            def render_GET(self, request, *, params):
                return MyResponse(page=params.page)

        request = _FakeRequest(args={})
        resource = MyResource()
        result = resource.render_GET(request)  # type: ignore[call-arg]

        self.assertEqual(request.responseCode, 400)
        data = json.loads(result)
        self.assertFalse(data['success'])


class TestAutoSerialization(unittest.TestCase):
    def setUp(self) -> None:
        clear_endpoint_registry()

    def tearDown(self) -> None:
        clear_endpoint_registry()

    def test_sync_response_model_serialized(self) -> None:
        """Handler returning a ResponseModel should be auto-serialized to bytes."""
        class MyResponse(ResponseModel):
            value: str

        class MyResource(Resource):
            @api_endpoint(
                path='/test',
                method='GET',
                operation_id='test',
                summary='Test',
                response_model=MyResponse,
            )
            def render_GET(self, request):
                return MyResponse(value='hello')

        request = _FakeRequest()
        resource = MyResource()
        result = resource.render_GET(request)

        self.assertIsInstance(result, bytes)
        data = json.loads(result)
        self.assertEqual(data['value'], 'hello')

    def test_status_code_from_model(self) -> None:
        """HTTP status code should be set from model's http_status_code ClassVar."""
        class MyError(ResponseModel):
            http_status_code: ClassVar[int] = 404
            message: str

        class MyResource(Resource):
            @api_endpoint(
                path='/test',
                method='GET',
                operation_id='test',
                summary='Test',
                response_model=MyError,
            )
            def render_GET(self, request):
                return MyError(message='not found')

        request = _FakeRequest()
        resource = MyResource()
        resource.render_GET(request)

        self.assertEqual(request.responseCode, 404)

    def test_200_status_code_for_success(self) -> None:
        """ResponseModel without custom status code should return 200."""
        class MyResponse(ResponseModel):
            value: str

        class MyResource(Resource):
            @api_endpoint(
                path='/test',
                method='GET',
                operation_id='test',
                summary='Test',
                response_model=MyResponse,
            )
            def render_GET(self, request):
                return MyResponse(value='ok')

        request = _FakeRequest()
        resource = MyResource()
        resource.render_GET(request)

        self.assertEqual(request.responseCode, 200)


class TestDeferredAutoSerialization(unittest.TestCase):
    def setUp(self) -> None:
        clear_endpoint_registry()

    def tearDown(self) -> None:
        clear_endpoint_registry()

    def test_deferred_response_model(self) -> None:
        """Deferred resolving to a ResponseModel should be auto-serialized."""
        class MyResponse(ResponseModel):
            value: str

        class MyResource(Resource):
            @api_endpoint(
                path='/test',
                method='GET',
                operation_id='test',
                summary='Test',
                response_model=MyResponse,
            )
            def render_GET(self, request):
                return succeed(MyResponse(value='deferred'))

        request = _FakeRequest()
        resource = MyResource()
        result = resource.render_GET(request)

        self.assertEqual(result, NOT_DONE_YET)
        self.assertTrue(request.finished)
        data = json.loads(b''.join(request.written))
        self.assertEqual(data['value'], 'deferred')

    def test_deferred_status_code(self) -> None:
        """Deferred resolving to error model should set correct status code."""
        class MyError(ResponseModel):
            http_status_code: ClassVar[int] = 503
            error: str

        class MyResource(Resource):
            @api_endpoint(
                path='/test',
                method='GET',
                operation_id='test',
                summary='Test',
                response_model=MyError,
            )
            def render_GET(self, request):
                return succeed(MyError(error='unavailable'))

        request = _FakeRequest()
        resource = MyResource()
        resource.render_GET(request)

        self.assertEqual(request.responseCode, 503)


class TestFallbackBehavior(unittest.TestCase):
    def setUp(self) -> None:
        clear_endpoint_registry()

    def tearDown(self) -> None:
        clear_endpoint_registry()

    def test_raw_bytes_passthrough(self) -> None:
        """Handler returning raw bytes should pass through unchanged."""
        class MyResource(Resource):
            @api_endpoint(
                path='/test',
                method='GET',
                operation_id='test',
                summary='Test',
            )
            def render_GET(self, request):
                return b'{"raw": true}'

        request = _FakeRequest()
        resource = MyResource()
        result = resource.render_GET(request)

        self.assertEqual(result, b'{"raw": true}')

    def test_not_done_yet_passthrough(self) -> None:
        """Handler returning NOT_DONE_YET directly should pass through."""
        class MyResource(Resource):
            @api_endpoint(
                path='/test',
                method='GET',
                operation_id='test2',
                summary='Test',
            )
            def render_GET(self, request):
                # Simulate manually handling the request
                request.write(b'manual')
                request.finish()
                return NOT_DONE_YET

        request = _FakeRequest()
        resource = MyResource()
        result = resource.render_GET(request)

        self.assertEqual(result, NOT_DONE_YET)
        self.assertTrue(request.finished)


class TestHeaders(unittest.TestCase):
    def setUp(self) -> None:
        clear_endpoint_registry()

    def tearDown(self) -> None:
        clear_endpoint_registry()

    def test_content_type_set(self) -> None:
        """Content-type header should be set automatically."""
        class MyResponse(ResponseModel):
            value: str

        class MyResource(Resource):
            @api_endpoint(
                path='/test',
                method='GET',
                operation_id='test',
                summary='Test',
                response_model=MyResponse,
            )
            def render_GET(self, request):
                return MyResponse(value='ok')

        request = _FakeRequest()
        resource = MyResource()
        resource.render_GET(request)

        self.assertEqual(
            request._headers[b'content-type'],
            b'application/json; charset=utf-8',
        )

    def test_cors_headers_set(self) -> None:
        """CORS headers should be set automatically."""
        class MyResponse(ResponseModel):
            value: str

        class MyResource(Resource):
            @api_endpoint(
                path='/test',
                method='GET',
                operation_id='test',
                summary='Test',
                response_model=MyResponse,
            )
            def render_GET(self, request):
                return MyResponse(value='ok')

        request = _FakeRequest()
        resource = MyResource()
        resource.render_GET(request)

        self.assertIn('Access-Control-Allow-Origin', request._headers)


class TestRequestBodyValidation(unittest.TestCase):
    def setUp(self) -> None:
        clear_endpoint_registry()

    def tearDown(self) -> None:
        clear_endpoint_registry()

    def test_valid_request_body(self) -> None:
        """Valid request body should be parsed and passed as body= kwarg."""
        from hathor.api.schemas import RequestModel

        class MyBody(RequestModel):
            name: str

        class MyResponse(ResponseModel):
            greeting: str

        class MyResource(Resource):
            @api_endpoint(
                path='/test',
                method='POST',
                operation_id='test',
                summary='Test',
                request_model=MyBody,
                response_model=MyResponse,
            )
            def render_POST(self, request, *, body):
                return MyResponse(greeting=f'Hello {body.name}')

        request = _FakeRequest(body={'name': 'World'})
        resource = MyResource()
        result = resource.render_POST(request)  # type: ignore[call-arg]

        data = json.loads(result)
        self.assertEqual(data['greeting'], 'Hello World')

    def test_invalid_request_body_returns_400(self) -> None:
        """Invalid request body should return 400 error."""
        from hathor.api.schemas import RequestModel

        class MyBody(RequestModel):
            name: str

        class MyResponse(ResponseModel):
            greeting: str

        class MyResource(Resource):
            @api_endpoint(
                path='/test',
                method='POST',
                operation_id='test2',
                summary='Test',
                request_model=MyBody,
                response_model=MyResponse,
            )
            def render_POST(self, request, *, body):
                return MyResponse(greeting=f'Hello {body.name}')

        # Missing required field
        request = _FakeRequest(body={})
        resource = MyResource()
        result = resource.render_POST(request)  # type: ignore[call-arg]

        self.assertEqual(request.responseCode, 400)
        data = json.loads(result)
        self.assertFalse(data['success'])

    def test_malformed_json_returns_400(self) -> None:
        """Malformed JSON body should return 400 error."""
        from hathor.api.schemas import RequestModel

        class MyBody(RequestModel):
            name: str

        class MyResponse(ResponseModel):
            greeting: str

        class MyResource(Resource):
            @api_endpoint(
                path='/test',
                method='POST',
                operation_id='test3',
                summary='Test',
                request_model=MyBody,
                response_model=MyResponse,
            )
            def render_POST(self, request, *, body):
                return MyResponse(greeting=f'Hello {body.name}')

        request = _FakeRequest()
        request.content = BytesIO(b'not json')
        resource = MyResource()
        result = resource.render_POST(request)  # type: ignore[call-arg]

        self.assertEqual(request.responseCode, 400)
        data = json.loads(result)
        self.assertFalse(data['success'])


class TestApiStatusSetFlag(unittest.TestCase):
    def setUp(self) -> None:
        clear_endpoint_registry()

    def tearDown(self) -> None:
        clear_endpoint_registry()

    def test_status_code_not_overridden_when_flag_set(self) -> None:
        """When _api_status_set is True, decorator should not override status code."""
        class MyError(ResponseModel):
            http_status_code: ClassVar[int] = 503
            error: str

        class MyResource(Resource):
            @api_endpoint(
                path='/test',
                method='GET',
                operation_id='test',
                summary='Test',
                response_model=MyError,
            )
            def render_GET(self, request):
                request._api_status_set = True
                request.setResponseCode(200)
                return MyError(error='overridden to 200')

        request = _FakeRequest()
        resource = MyResource()
        resource.render_GET(request)

        # Status should remain 200, not be overridden to 503
        self.assertEqual(request.responseCode, 200)


class TestDeferredErrbackHandling(unittest.TestCase):
    def setUp(self) -> None:
        clear_endpoint_registry()

    def tearDown(self) -> None:
        clear_endpoint_registry()

    def test_deferred_failure_returns_500(self) -> None:
        """An endpoint returning a Deferred that fires an errback should return 500."""
        class MyResponse(ResponseModel):
            value: str

        class MyResource(Resource):
            @api_endpoint(
                path='/test',
                method='GET',
                operation_id='test_errback',
                summary='Test',
                response_model=MyResponse,
            )
            def render_GET(self, request):
                return fail(Exception('something went wrong'))

        request = _FakeRequest()
        resource = MyResource()
        result = resource.render_GET(request)

        self.assertEqual(result, NOT_DONE_YET)
        self.assertTrue(request.finished)
        self.assertEqual(request.responseCode, 500)
        data = request.json_value()
        self.assertIn('error', data)
        self.assertIn('something went wrong', data['error'])

    def test_deferred_callback_exception_returns_500(self) -> None:
        """If the Deferred callback raises, the errback should catch it and return 500."""
        class MyResponse(ResponseModel):
            value: str

        class MyResource(Resource):
            @api_endpoint(
                path='/test',
                method='GET',
                operation_id='test_errback2',
                summary='Test',
                response_model=MyResponse,
            )
            def render_GET(self, request):
                d = succeed('raw string')
                # The callback chain: succeed('raw string') -> _handle_deferred_result
                # will try to call request.write('raw string') with a str, which
                # in real Twisted would fail. But our _FakeRequest.write accepts anything.
                # Instead, add a callback that explicitly raises.
                d.addCallback(lambda _: (_ for _ in ()).throw(RuntimeError('callback boom')))
                return d

        request = _FakeRequest()
        resource = MyResource()
        result = resource.render_GET(request)

        self.assertEqual(result, NOT_DONE_YET)
        self.assertTrue(request.finished)
        self.assertEqual(request.responseCode, 500)
        data = request.json_value()
        self.assertIn('error', data)
        self.assertIn('callback boom', data['error'])
