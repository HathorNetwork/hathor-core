"""Tests for AsyncAPI 3.0 specification generator."""
import unittest
from typing import Literal

from pydantic import Field

from hathor.api.asyncapi.decorators import WsMessageMetadata, get_ws_message_meta, ws_message
from hathor.api.asyncapi.generator import (
    AsyncAPIGenerator,
    ChannelDefinition,
    MessageDefinition,
    MessageDirection,
)
from hathor.api.schema_utils import SchemaRegistryMixin
from hathor.utils.pydantic import BaseModel


class TestSchemaRegistryMixin(unittest.TestCase):
    """Tests for the shared SchemaRegistryMixin."""

    def setUp(self) -> None:
        class _Gen(SchemaRegistryMixin):
            def __init__(self):
                self._schemas: dict = {}
        self.gen = _Gen()

    def test_get_schema_ref_registers_and_returns_ref(self) -> None:
        class MyModel(BaseModel):
            value: str

        ref = self.gen._get_schema_ref(MyModel)
        self.assertEqual(ref, {'$ref': '#/components/schemas/MyModel'})
        self.assertIn('MyModel', self.gen._schemas)

    def test_get_schema_ref_idempotent(self) -> None:
        class MyModel(BaseModel):
            value: str

        ref1 = self.gen._get_schema_ref(MyModel)
        ref2 = self.gen._get_schema_ref(MyModel)
        self.assertEqual(ref1, ref2)

    def test_flatten_schemas_hoists_defs(self) -> None:
        class Inner(BaseModel):
            name: str

        class Outer(BaseModel):
            items: list[Inner]

        self.gen._get_schema_ref(Outer)
        flat = self.gen._flatten_schemas()

        self.assertIn('Outer', flat)
        self.assertIn('Inner', flat)
        self.assertNotIn('$defs', flat.get('Outer', {}))

    def test_flatten_schemas_no_defs(self) -> None:
        class Simple(BaseModel):
            value: int

        self.gen._get_schema_ref(Simple)
        flat = self.gen._flatten_schemas()

        self.assertIn('Simple', flat)
        self.assertEqual(len(flat), 1)


class TestWsMessageDecorator(unittest.TestCase):
    """Tests for the @ws_message decorator."""

    def test_decorator_stores_metadata(self) -> None:
        @ws_message(
            name='testMsg',
            direction=MessageDirection.SEND,
            summary='A test message',
            description='Detailed description',
            tags=['test'],
        )
        class TestModel(BaseModel):
            value: str

        meta = get_ws_message_meta(TestModel)
        self.assertIsNotNone(meta)
        self.assertIsInstance(meta, WsMessageMetadata)
        self.assertEqual(meta.name, 'testMsg')
        self.assertEqual(meta.direction, MessageDirection.SEND)
        self.assertEqual(meta.summary, 'A test message')
        self.assertEqual(meta.description, 'Detailed description')
        self.assertEqual(meta.tags, ['test'])

    def test_decorator_without_optional_fields(self) -> None:
        @ws_message(
            name='minimal',
            direction=MessageDirection.RECEIVE,
            summary='Minimal message',
        )
        class MinimalModel(BaseModel):
            pass

        meta = get_ws_message_meta(MinimalModel)
        self.assertIsNotNone(meta)
        self.assertIsNone(meta.description)
        self.assertEqual(meta.tags, [])

    def test_undecorated_model_returns_none(self) -> None:
        class PlainModel(BaseModel):
            value: str

        meta = get_ws_message_meta(PlainModel)
        self.assertIsNone(meta)


class TestAsyncAPIGenerator(unittest.TestCase):
    """Tests for the AsyncAPIGenerator."""

    def test_basic_channel_with_message_definitions(self) -> None:
        """MessageDefinition instances should work as before."""
        class PingModel(BaseModel):
            type: Literal['ping'] = 'ping'

        class PongModel(BaseModel):
            type: Literal['pong'] = 'pong'

        channel = ChannelDefinition(
            channel_id='testWs',
            address='/test',
            title='Test WS',
            description='A test WebSocket',
            messages=[
                MessageDefinition(
                    name='ping',
                    model=PingModel,
                    direction=MessageDirection.RECEIVE,
                    summary='Ping',
                ),
                MessageDefinition(
                    name='pong',
                    model=PongModel,
                    direction=MessageDirection.SEND,
                    summary='Pong',
                ),
            ],
        )

        gen = AsyncAPIGenerator()
        gen.add_channel(channel)
        spec = gen.generate()

        self.assertEqual(spec['asyncapi'], '3.0.0')
        self.assertIn('testWs', spec['channels'])
        self.assertIn('ping', spec['channels']['testWs']['messages'])
        self.assertIn('pong', spec['channels']['testWs']['messages'])
        self.assertIn('testWsReceive', spec['operations'])
        self.assertIn('testWsSend', spec['operations'])

    def test_channel_with_decorated_model_classes(self) -> None:
        """Model classes decorated with @ws_message should be auto-resolved."""
        @ws_message(
            name='request',
            direction=MessageDirection.RECEIVE,
            summary='A request',
            description='Request desc',
            tags=['test'],
        )
        class RequestModel(BaseModel):
            type: Literal['request'] = 'request'

        @ws_message(
            name='response',
            direction=MessageDirection.SEND,
            summary='A response',
        )
        class ResponseModel(BaseModel):
            type: Literal['response'] = 'response'

        channel = ChannelDefinition(
            channel_id='testWs',
            address='/test',
            title='Test WS',
            description='A test WebSocket',
            messages=[RequestModel, ResponseModel],
        )

        gen = AsyncAPIGenerator()
        gen.add_channel(channel)
        spec = gen.generate()

        # Messages should be resolved from decorator metadata
        messages = spec['channels']['testWs']['messages']
        self.assertIn('request', messages)
        self.assertIn('response', messages)
        self.assertEqual(messages['request']['summary'], 'A request')
        self.assertEqual(messages['request']['description'], 'Request desc')
        self.assertEqual(messages['request']['tags'], [{'name': 'test'}])
        self.assertEqual(messages['response']['summary'], 'A response')

        # Operations should be correct
        self.assertIn('testWsReceive', spec['operations'])
        self.assertIn('testWsSend', spec['operations'])

    def test_undecorated_model_raises_error(self) -> None:
        """Passing an undecorated model class should raise ValueError."""
        class PlainModel(BaseModel):
            value: str

        channel = ChannelDefinition(
            channel_id='testWs',
            address='/test',
            title='Test WS',
            description='Test',
            messages=[PlainModel],
        )

        gen = AsyncAPIGenerator()
        gen.add_channel(channel)
        with self.assertRaises(ValueError) as ctx:
            gen.generate()
        self.assertIn('PlainModel', str(ctx.exception))
        self.assertIn('@ws_message', str(ctx.exception))

    def test_mixed_definitions_and_classes(self) -> None:
        """Mix of MessageDefinition and decorated classes should work."""
        class ExplicitModel(BaseModel):
            value: str

        @ws_message(
            name='decorated',
            direction=MessageDirection.SEND,
            summary='Decorated',
        )
        class DecoratedModel(BaseModel):
            value: int

        channel = ChannelDefinition(
            channel_id='testWs',
            address='/test',
            title='Test WS',
            description='Test',
            messages=[
                MessageDefinition(
                    name='explicit',
                    model=ExplicitModel,
                    direction=MessageDirection.RECEIVE,
                    summary='Explicit',
                ),
                DecoratedModel,
            ],
        )

        gen = AsyncAPIGenerator()
        gen.add_channel(channel)
        spec = gen.generate()

        messages = spec['channels']['testWs']['messages']
        self.assertIn('explicit', messages)
        self.assertIn('decorated', messages)

    def test_schemas_are_flattened(self) -> None:
        """Nested $defs should be hoisted to components/schemas."""
        class Inner(BaseModel):
            name: str

        @ws_message(
            name='outer',
            direction=MessageDirection.SEND,
            summary='Outer',
        )
        class Outer(BaseModel):
            items: list[Inner]

        channel = ChannelDefinition(
            channel_id='testWs',
            address='/test',
            title='Test WS',
            description='Test',
            messages=[Outer],
        )

        gen = AsyncAPIGenerator()
        gen.add_channel(channel)
        spec = gen.generate()

        schemas = spec.get('components', {}).get('schemas', {})
        self.assertIn('Outer', schemas)
        self.assertIn('Inner', schemas)
        self.assertNotIn('$defs', schemas.get('Outer', {}))


class TestFullSpecGeneration(unittest.TestCase):
    """Test the full create_hathor_asyncapi_generator() produces valid spec."""

    def test_full_spec_generation(self) -> None:
        from hathor.api.asyncapi.generator import create_hathor_asyncapi_generator

        generator = create_hathor_asyncapi_generator()
        spec = generator.generate()

        # Check top-level structure
        self.assertEqual(spec['asyncapi'], '3.0.0')
        self.assertIn('info', spec)
        self.assertIn('channels', spec)
        self.assertIn('operations', spec)
        self.assertIn('components', spec)

        # Check all three channels are present
        self.assertIn('adminWs', spec['channels'])
        self.assertIn('eventWs', spec['channels'])
        self.assertIn('miningWs', spec['channels'])

        # Check operations exist for each channel
        self.assertIn('adminWsReceive', spec['operations'])
        self.assertIn('adminWsSend', spec['operations'])
        self.assertIn('eventWsReceive', spec['operations'])
        self.assertIn('eventWsSend', spec['operations'])
        self.assertIn('miningWsReceive', spec['operations'])
        self.assertIn('miningWsSend', spec['operations'])

        # Check admin WS has all expected messages
        admin_msgs = spec['channels']['adminWs']['messages']
        self.assertIn('ping', admin_msgs)
        self.assertIn('pong', admin_msgs)
        self.assertIn('subscribeAddress', admin_msgs)
        self.assertIn('dashboardMetrics', admin_msgs)
        self.assertIn('streamBegin', admin_msgs)

        # Check event WS has expected messages
        event_msgs = spec['channels']['eventWs']['messages']
        self.assertIn('startStream', event_msgs)
        self.assertIn('ack', event_msgs)
        self.assertIn('stopStream', event_msgs)
        self.assertIn('event', event_msgs)
        self.assertIn('invalidRequest', event_msgs)

        # Check mining WS has expected messages
        mining_msgs = spec['channels']['miningWs']['messages']
        self.assertIn('miningRefresh', mining_msgs)
        self.assertIn('miningSubmit', mining_msgs)
        self.assertIn('miningNotify', mining_msgs)
        self.assertIn('jsonRpcError', mining_msgs)

        # Check schemas exist
        schemas = spec['components']['schemas']
        self.assertGreater(len(schemas), 0)
