import os

from hathor.exception import InvalidNewTransaction
from hathor.nanocontracts import OnChainBlueprint
from hathor.nanocontracts.exception import OCBInvalidScript
from tests import unittest


def _load_file(filename: str) -> bytes:
    cur_dir = os.path.dirname(__file__)
    filepath = os.path.join(cur_dir, filename)
    content = bytearray()
    with open(filepath, 'rb') as nc_file:
        for line in nc_file.readlines():
            content.extend(line)
    return bytes(content)


ZLIB_BOMB: bytes = _load_file('bomb.zlib')


class OnChainBlueprintScriptTestCase(unittest.TestCase):
    _enable_sync_v1 = True
    _enable_sync_v2 = True
    use_memory_storage = True

    def setUp(self):
        super().setUp()
        self.manager = self.create_peer('testnet')
        self.verification_service = self.manager.verification_service

    def _create_on_chain_blueprint(self, nc_code: bytes) -> OnChainBlueprint:
        from hathor.nanocontracts.on_chain_blueprint import Code, CodeKind

        code = Code(CodeKind.PYTHON_GZIP, nc_code)
        timestamp = self.manager.tx_storage.latest_timestamp + 1
        parents = self.manager.get_new_tx_parents(timestamp)
        blueprint = OnChainBlueprint(
            weight=1,
            inputs=[],
            outputs=[],
            parents=parents,
            storage=self.manager.tx_storage,
            timestamp=timestamp,
            code=code,
        )
        blueprint.weight = self.manager.daa.minimum_tx_weight(blueprint)
        self.manager.cpu_mining_service.resolve(blueprint)
        self.manager.reactor.advance(2)
        return blueprint

    def test_forbid_eval(self) -> None:
        blueprint = self._create_on_chain_blueprint(b'''eval("print('foo')")''')
        # generically an InvalidNewTransaction should happen:
        with self.assertRaises(InvalidNewTransaction):
            self.manager.vertex_handler.on_new_vertex(blueprint, fails_silently=False)
        # but more specifically, it should be because of a OCBInvalidScript (I'm not sure if we can check the "from" of
        # the InvalidNewTransaction that we check for previously), also it should happen during the
        # verify_without_storage, we don't need it to be late like in verify_basic or verify
        with self.assertRaises(OCBInvalidScript):
            self.verification_service.verify_without_storage(blueprint)

    def test_zlib_bomb(self) -> None:
        from struct import error as StructError

        from hathor.nanocontracts.on_chain_blueprint import ON_CHAIN_BLUEPRINT_VERSION, CodeKind
        from hathor.transaction.util import int_to_bytes
        from hathor.transaction.vertex_parser import VertexParser

        blueprint = self._create_on_chain_blueprint(b'')
        code = bytearray()
        code.extend(int_to_bytes(ON_CHAIN_BLUEPRINT_VERSION, 1))
        code_type = bytes(CodeKind.PYTHON_GZIP)
        code.extend(int_to_bytes(len(ZLIB_BOMB) + len(code_type) + 1, 4))
        code.extend(code_type)
        code.append(0)
        code.extend(ZLIB_BOMB)
        blueprint.serialize_code = lambda: code  # type: ignore[method-assign]
        serialized_blueprint = bytes(blueprint)
        parser = VertexParser(settings=self._settings)
        with self.assertRaises(StructError) as cm:
            _ = parser.deserialize(serialized_blueprint)
        cause = cm.exception.__cause__
        self.assertIsInstance(cause, ValueError)
        self.assertEqual(cause.args, ('Decompressed code is too long.',))
