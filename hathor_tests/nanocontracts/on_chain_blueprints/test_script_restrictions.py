import os
from textwrap import dedent

from hathor.exception import InvalidNewTransaction
from hathor.nanocontracts import OnChainBlueprint
from hathor.nanocontracts.exception import OCBInvalidScript
from hathor_tests import unittest
from hathor_tests.nanocontracts.on_chain_blueprints.utils import get_ocb_private_key


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
    def setUp(self):
        super().setUp()
        self.manager = self.create_peer('unittests')
        self.verification_service = self.manager.verification_service

    def _ocb_mine(self, blueprint: OnChainBlueprint) -> None:
        self.manager.cpu_mining_service.resolve(blueprint)
        self.manager.reactor.advance(2)

    def _create_on_chain_blueprint(self, nc_code: str) -> OnChainBlueprint:
        from hathor.nanocontracts.on_chain_blueprint import Code

        code = Code.from_python_code(nc_code, self._settings)
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
        blueprint.sign(get_ocb_private_key())
        self._ocb_mine(blueprint)
        return blueprint

    def _test_forbid_syntax(self, code: str, *, syntax_errors: tuple[str, ...]) -> None:
        blueprint = self._create_on_chain_blueprint(code)
        with self.assertRaises(InvalidNewTransaction) as cm:
            self.manager.vertex_handler.on_new_relayed_vertex(blueprint)
        assert isinstance(cm.exception.__cause__, OCBInvalidScript)
        assert isinstance(cm.exception.__cause__.__cause__, SyntaxError)
        assert cm.exception.args[0] == 'full validation failed: forbidden syntax'
        # The first error is always the one that makes the tx fail
        assert cm.exception.__cause__.__cause__.args[0] == syntax_errors[0]

        self._test_expected_syntax_errors(code, syntax_errors=syntax_errors)

    def _test_expected_syntax_errors(self, code: str, *, syntax_errors: tuple[str, ...],) -> None:
        blueprint = self._create_on_chain_blueprint(code)
        rules = self.manager.verification_service.verifiers.on_chain_blueprint.blueprint_code_rules()
        errors = []
        for rule in rules:
            try:
                rule(blueprint)
            except SyntaxError as e:
                errors.append(e)
            except Exception:
                # this test function is not interested in non-syntax errors
                pass

        assert len(errors) == len(syntax_errors)
        for error, expected in zip(errors, syntax_errors, strict=True):
            assert error.args[0] == expected

    def test_forbid_import(self) -> None:
        self._test_forbid_syntax(
            'import os',
            syntax_errors=('Import statements are not allowed.',),
        )

    def test_forbid_import_from(self) -> None:
        self._test_forbid_syntax(
            'from os import path',
            syntax_errors=('Importing from "os" is not allowed.',),
        )
        # XXX: only math.ceil and math.floor are currently allowed, log should error
        self._test_forbid_syntax(
            'from math import log',
            syntax_errors=('Importing "log" from "math" is not allowed.',),
        )

    def test_forbid_try_except(self) -> None:
        self._test_forbid_syntax(
            'try:\n    ...\nexcept:\n    ...',
            syntax_errors=('Try/Except blocks are not allowed.',),
        )

    def test_forbid_names_blacklist(self) -> None:
        forbidden_cases = {
            'compile': [
                r'''code = compile('print("foo")')''',
            ],
            'delattr': [
                '''x = dict()\nx.foo = 1\ndelattr(x, 'foo')''',
            ],
            'dir': [
                '''x = dir()''',
            ],
            'eval': [
                '''x = eval('1+1')''',
            ],
            'exec': [
                '''exec('x=1+1')''',
            ],
            'getattr': [
                '''x = dict()\nx.foo = 1\ny = getattr(x, 'foo')''',
            ],
            'globals': [
                '''x = 1\ny = globals()['x']''',
            ],
            'hasattr': [
                '''x = dict()\ny = hasattr(x, 'foo')''',
            ],
            'input': [
                '''x = input()''',
            ],
            'locals': [
                '''x = 1\ny = locals()['x']''',
            ],
            'open': [
                '''x = open('foo.txt')''',
            ],
            'setattr': [
                '''x = dict()\nsetattr(x, 'foo', 1)''',
            ],
            'vars': [
                '''x = vars()''',
            ],
        }
        for attr, codes in forbidden_cases.items():
            for code in codes:
                self._test_forbid_syntax(code, syntax_errors=(f'Usage or reference to {attr} is not allowed.',))

        forbidden_cases_with_dunder = {
            '__builtins__': [
                r'''x = __builtins__('dir')''',
                r'''y = __builtins__.dir''',
            ],
            '__import__': [
                r'''sys = __import__('sys')''',
                r'''os = __import__('os.path')''',
                r'''path = __import__('os.path', fromlist=[None])''',
            ],
        }
        for attr, codes in forbidden_cases_with_dunder.items():
            for code in codes:
                self._test_forbid_syntax(
                    code,
                    syntax_errors=(
                        'script contains dunder text',
                        f'Usage or reference to {attr} is not allowed.',
                    )
                )

    def test_forbid_internal_attr(self) -> None:
        self._test_forbid_syntax(
            'x = 1\nx.__class__',
            syntax_errors=(
                'script contains dunder text',
                'Access to internal attributes and methods is not allowed.',
            ),
        )
        self._test_forbid_syntax(
            'x = 1\nx.__runner',
            syntax_errors=(
                'script contains dunder text',
                'Access to internal attributes and methods is not allowed.',
            ),
        )
        self._test_forbid_syntax(
            'x = 1\nx._Context__runner',
            syntax_errors=(
                'script contains dunder text',
                'Access to internal attributes and methods is not allowed.',
            ),
        )
        self._test_forbid_syntax(
            'x = log.__entries__',
            syntax_errors=(
                'script contains dunder text',
                'Access to internal attributes and methods is not allowed.',
            ),
        )
        self._test_forbid_syntax(
            'x().__setattr__',
            syntax_errors=(
                'script contains dunder text',
                'Access to internal attributes and methods is not allowed.',
            ),
        )
        self._test_forbid_syntax(
            'super().__setattr__',
            syntax_errors=(
                'script contains dunder text',
                'Access to internal attributes and methods is not allowed.',
            ),
        )
        self._test_forbid_syntax(
            '(lambda: object).__setattr__',
            syntax_errors=(
                'script contains dunder text',
                'Access to internal attributes and methods is not allowed.',
            ),
        )
        self._test_forbid_syntax(
            '(lambda: object)().__setattr__',
            syntax_errors=(
                'script contains dunder text',
                'Access to internal attributes and methods is not allowed.',
            ),
        )
        self._test_forbid_syntax(
            '(object,)[0].__setattr__',
            syntax_errors=(
                'script contains dunder text',
                'Access to internal attributes and methods is not allowed.',
            ),
        )

    def test_forbid_dunder_names(self) -> None:
        self._test_forbid_syntax(
            '__x__ = 123',
            syntax_errors=(
                'script contains dunder text',
                'Using dunder names is not allowed.',
            ),
        )
        self._test_forbid_syntax(
            'x = "__x__"',
            syntax_errors=('script contains dunder text',),
        )
        self._test_forbid_syntax(
            '__',
            syntax_errors=(
                'script contains dunder text',
                'Using dunder names is not allowed.',
            ),
        )
        self._test_forbid_syntax(
            dedent('''
                class Foo:
                    __slots__ = ()
            '''),
            syntax_errors=(
                'script contains dunder text',
                'Using dunder names is not allowed.',
            ),
        )
        self._test_forbid_syntax(
            dedent('''
                class Foo:
                    __match_args__ = ('__dict__',)
            '''),
            syntax_errors=(
                'script contains dunder text',
                'Using dunder names is not allowed.',
            ),
        )

    def test_forbid_magic_methods(self) -> None:
        self._test_forbid_syntax(
            dedent('''
                class Foo:
                    def __init__(self):
                        pass
            '''),
            syntax_errors=(
                'script contains dunder text',
                'magic methods are not allowed',
            ),
        )
        self._test_forbid_syntax(
            dedent('''
                class Foo:
                    def __new__(self):
                        pass
            '''),
            syntax_errors=(
                'script contains dunder text',
                'magic methods are not allowed',
            ),
        )
        self._test_forbid_syntax(
            dedent('''
                class Foo:
                    def __setattr__(self):
                        pass
            '''),
            syntax_errors=(
                'script contains dunder text',
                'magic methods are not allowed',
            ),
        )

    def test_forbid_match_dunder(self) -> None:
        self._test_forbid_syntax(
            dedent('''
                match 123:
                    case int(__dict__=my_dict):
                        pass
            '''),
            syntax_errors=(
                'script contains dunder text',
                'cannot match on dunder name',
            )
        )
        self._test_forbid_syntax(
            dedent('''
                match 123:
                    case {'__dict__': 123}:
                        pass
            '''),
            syntax_errors=(
                'script contains dunder text',
                'cannot match on dunder name',
            ),
        )

        # These are allowed:

        self._test_expected_syntax_errors(
            dedent('''
                match 123:
                    case int():
                        pass
            '''),
            syntax_errors=(),
        )

        self._test_expected_syntax_errors(
            dedent('''
                match 123:
                    case int(real=real):
                        pass
            '''),
            syntax_errors=(),
        )

        self._test_expected_syntax_errors(
            dedent('''
                match 123:
                    case {}:
                        pass
            '''),
            syntax_errors=(),
        )

        self._test_expected_syntax_errors(
            dedent('''
                match 123:
                    case {'real': 123}:
                        pass
            '''),
            syntax_errors=(),
        )

    def test_forbid_async_fn(self) -> None:
        self._test_forbid_syntax(
            'async def foo():\n    ...',
            syntax_errors=('Async functions are not allowed.',)
        )

    def test_forbid_float_literal(self) -> None:
        self._test_forbid_syntax(
            'a = 3.14',
            syntax_errors=('Float literals are not allowed.',)
        )
        self._test_forbid_syntax(
            'a = 3.',
            syntax_errors=('Float literals are not allowed.',)
        )
        self._test_forbid_syntax(
            'a = .14',
            syntax_errors=('Float literals are not allowed.',)
        )

    def test_forbid_complex_literal(self) -> None:
        self._test_forbid_syntax(
            'a = 1j',
            syntax_errors=('Complex literals are not allowed.',)
        )

    def test_forbid_float_division(self) -> None:
        self._test_forbid_syntax(
            'a = 1 / 2',
            syntax_errors=('Simple / division results in float, use // instead.',)
        )

    def test_forbid_await_syntax(self) -> None:
        # XXX: it is normally forbidden to use await outside an async context, and since async functions cannot be
        #      defined, it isn't possible to make a realistic code that will fail with await (also applies to other
        #      syntax nodes as'async for' and 'async with'), however the parser will normally accept this because it
        #      forms a valid syntax tree
        self._test_forbid_syntax(
            'x = await foo()',
            syntax_errors=(
                'Await is not allowed.',
                "'await' outside function",
            ),
        )
        self._test_forbid_syntax(
            'async for i in range(10):\n    ...',
            syntax_errors=(
                'Async loops are not allowed.',
                "'async for' outside async function",
            ),
        )
        self._test_forbid_syntax(
            'async with foo():\n    ...',
            syntax_errors=(
                'Async contexts are not allowed.',
                "'async with' outside async function",
            ),
        )

    def test_invalid_python_syntax(self) -> None:
        code = 'x ++= 1'
        blueprint = self._create_on_chain_blueprint(code)
        with self.assertRaises(InvalidNewTransaction) as cm:
            self.manager.vertex_handler.on_new_relayed_vertex(blueprint)
        assert isinstance(cm.exception.__cause__, OCBInvalidScript)
        assert isinstance(cm.exception.__cause__.__cause__, SyntaxError)
        assert cm.exception.args[0] == 'full validation failed: Could not correctly parse the script'

    def test_blueprint_type_not_a_class(self) -> None:
        blueprint = self._create_on_chain_blueprint(r'''
from hathor import export
@export
def Foo():
    pass
''')
        with self.assertRaises(InvalidNewTransaction) as cm:
            self.manager.vertex_handler.on_new_relayed_vertex(blueprint)
        assert isinstance(cm.exception.__cause__, OCBInvalidScript)
        assert cm.exception.args[0] == 'full validation failed: Could not find a main Blueprint definition'

    def test_blueprint_type_not_blueprint_subclass(self) -> None:
        blueprint = self._create_on_chain_blueprint(r'''
from hathor import export
@export
class Foo():
    pass
''')
        with self.assertRaises(InvalidNewTransaction) as cm:
            self.manager.vertex_handler.on_new_relayed_vertex(blueprint)
        assert isinstance(cm.exception.__cause__, OCBInvalidScript)
        assert cm.exception.args[0] == 'full validation failed: exported Blueprint is not a Blueprint subclass'

    def test_zlib_bomb(self) -> None:
        from struct import error as StructError

        from hathor.nanocontracts.on_chain_blueprint import ON_CHAIN_BLUEPRINT_VERSION, CodeKind
        from hathor.transaction.util import int_to_bytes
        from hathor.transaction.vertex_parser import VertexParser

        blueprint = self._create_on_chain_blueprint('')
        code = bytearray()
        code.extend(int_to_bytes(ON_CHAIN_BLUEPRINT_VERSION, 1))
        code_type = bytes(CodeKind.PYTHON_ZLIB)
        code.extend(int_to_bytes(len(ZLIB_BOMB) + len(code_type) + 1, 4))
        code.extend(code_type)
        code.extend(ZLIB_BOMB)
        blueprint.serialize_code = lambda: code  # type: ignore[method-assign]
        serialized_blueprint = bytes(blueprint)
        parser = VertexParser(settings=self._settings)
        with self.assertRaises(StructError) as cm:
            _ = parser.deserialize(serialized_blueprint)
        cause = cm.exception.__cause__
        self.assertIsInstance(cause, ValueError)
        self.assertEqual(cause.args, ('Decompressed code is too long.',))
