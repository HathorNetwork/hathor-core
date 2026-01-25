#  Copyright 2024 Hathor Labs
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

import ast
from typing import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from hathor.conf.settings import HathorSettings
from hathor.crypto.util import get_address_b58_from_public_key_bytes, get_public_key_from_bytes_compressed
from hathor.nanocontracts import OnChainBlueprint
from hathor.nanocontracts.custom_builtins import AST_NAME_BLACKLIST
from hathor.nanocontracts.exception import NCInvalidPubKey, NCInvalidSignature, OCBInvalidScript, OCBPubKeyNotAllowed
from hathor.nanocontracts.on_chain_blueprint import PYTHON_CODE_COMPAT_VERSION
from hathor.nanocontracts.sandbox import ALLOWED_IMPORTS


class _RestrictionsVisitor(ast.NodeVisitor):
    def visit_Interactive(self, node: ast.Interactive) -> None:
        raise AssertionError('mode="single" must not be used for parsing')

    def visit_Expression(self, node: ast.Expression) -> None:
        raise AssertionError('mode="eval" must not be used for parsing')

    def visit_FunctionType(self, node: ast.Expression) -> None:
        raise AssertionError('mode="func_type" must not be used for parsing')

    def visit_Import(self, node: ast.Import) -> None:
        raise SyntaxError('Import statements are not allowed.')

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module not in ALLOWED_IMPORTS:
            raise SyntaxError(f'Importing from "{node.module}" is not allowed.')
        allowed_fromlist = ALLOWED_IMPORTS[node.module]
        for import_what in node.names:
            if import_what.name not in allowed_fromlist:
                raise SyntaxError(f'Importing "{import_what.name}" from "{node.module}" is not allowed.')

    def visit_Try(self, node: ast.Try) -> None:
        raise SyntaxError('Try/Except blocks are not allowed.')

    def visit_Name(self, node: ast.Name) -> None:
        assert isinstance(node.id, str)
        if node.id in AST_NAME_BLACKLIST:
            raise SyntaxError(f'Usage or reference to {node.id} is not allowed.')
        if '__' in node.id:
            raise SyntaxError('Using dunder names is not allowed.')
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        assert isinstance(node.attr, str)
        if '__' in node.attr:
            raise SyntaxError('Access to internal attributes and methods is not allowed.')
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        assert isinstance(node.name, str)
        if '__' in node.name:
            raise SyntaxError('magic methods are not allowed')
        self.generic_visit(node)

    def visit_MatchClass(self, node: ast.MatchClass) -> None:
        for name in node.kwd_attrs:
            assert isinstance(name, str)
            if '__' in name:
                raise SyntaxError('cannot match on dunder name')
        self.generic_visit(node)

    def visit_MatchMapping(self, node: ast.MatchMapping) -> None:
        for name in node.keys:
            assert isinstance(name, ast.Constant)
            assert isinstance(name.value, str)
            if '__' in name.value:
                raise SyntaxError('cannot match on dunder name')
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        raise SyntaxError('Async functions are not allowed.')

    def visit_Await(self, node: ast.Await) -> None:
        raise SyntaxError('Await is not allowed.')

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        raise SyntaxError('Async loops are not allowed.')

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        raise SyntaxError('Async contexts are not allowed.')

    def visit_Constant(self, node: ast.Constant) -> None:
        match node.value:
            case float():
                raise SyntaxError('Float literals are not allowed.')
            case complex():
                raise SyntaxError('Complex literals are not allowed.')
            case _:
                self.generic_visit(node)

    def visit_Div(self, node: ast.Div) -> None:
        raise SyntaxError('Simple / division results in float, use // instead.')


class _SearchDecorator(ast.NodeVisitor):
    def __init__(self, name: str) -> None:
        self.search_name = name
        self.found = False

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for decorator in node.decorator_list:
            decorator_name: str
            if isinstance(decorator, ast.Name):
                decorator_name = decorator.id
            elif isinstance(decorator, ast.Call):
                if isinstance(decorator.func, ast.Name):
                    decorator_name = decorator.func.id
                else:
                    continue  # don't search invalid cases
            else:
                continue  # don't search invalid cases
            if decorator_name == self.search_name:
                self.found = True
                return
        self.generic_visit(node)


class OnChainBlueprintVerifier:
    __slots__ = ('_settings',)

    def __init__(self, *, settings: HathorSettings):
        self._settings = settings

    def verify_pubkey_is_allowed(self, tx: OnChainBlueprint) -> None:
        """Verify if the on-chain blueprint's pubkey is allowed."""
        if self._settings.NC_ON_CHAIN_BLUEPRINT_RESTRICTED:
            address = get_address_b58_from_public_key_bytes(tx.nc_pubkey)
            if address not in self._settings.NC_ON_CHAIN_BLUEPRINT_ALLOWED_ADDRESSES:
                raise OCBPubKeyNotAllowed(f'nc_pubkey with address {address} is not allowed')

    def verify_nc_signature(self, tx: OnChainBlueprint) -> None:
        """Verify if the creatos's signature is valid."""
        data = tx.get_sighash_all_data()

        try:
            pubkey = get_public_key_from_bytes_compressed(tx.nc_pubkey)
        except ValueError as e:
            # pubkey is not compressed public key
            raise NCInvalidPubKey('nc_pubkey is not a public key') from e

        try:
            pubkey.verify(tx.nc_signature, data, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature as e:
            raise NCInvalidSignature from e

    def _get_python_code_ast(self, tx: OnChainBlueprint) -> ast.Module:
        from hathor.nanocontracts.on_chain_blueprint import CodeKind
        assert tx.code.kind == CodeKind.PYTHON_ZLIB, 'only Python+Gzip is supported'
        if tx._ast_cache is not None:
            return tx._ast_cache
        # XXX: feature_version is a best-effort compatibility, some subtle cases could break, which is important to
        # deal with, so this isn't a definitive solution
        # XXX: consider this:
        # Signature:
        # ast.parse(
        #     source,
        #     filename='<unknown>',
        #     mode='exec',
        #     *,
        #     type_comments=False,
        #     feature_version=None,
        # )
        # Source:
        # def parse(source, filename='<unknown>', mode='exec', *,
        #           type_comments=False, feature_version=None):
        #     """
        #     Parse the source into an AST node.
        #     Equivalent to compile(source, filename, mode, PyCF_ONLY_AST).
        #     Pass type_comments=True to get back type comments where the syntax allows.
        #     """
        #     flags = PyCF_ONLY_AST
        #     if type_comments:
        #         flags |= PyCF_TYPE_COMMENTS
        #     if feature_version is None:
        #         feature_version = -1
        #     elif isinstance(feature_version, tuple):
        #         major, minor = feature_version  # Should be a 2-tuple.
        #         if major != 3:
        #             raise ValueError(f"Unsupported major version: {major}")
        #         feature_version = minor
        #     # Else it should be an int giving the minor version for 3.x.
        #     return compile(source, filename, mode, flags,
        #                    _feature_version=feature_version)
        # XXX: in practice we want to use ast.parse, but we need specify `dont_inherit=True` to prevent the current
        #      module's `from __future__ ...` imports from affecting the compilation, `_feature_version` is a private
        #      argument, so we have to be mindful of this whenever there's an update to Python's version
        parsed_tree = compile(
            source=tx.code.text,
            filename=f'<{tx.hash.hex()}.code>',
            mode='exec',
            flags=ast.PyCF_ONLY_AST,
            dont_inherit=True,
            optimize=0,
            _feature_version=PYTHON_CODE_COMPAT_VERSION[1],
        )
        assert isinstance(parsed_tree, ast.Module)
        tx._ast_cache = parsed_tree
        return parsed_tree

    def blueprint_code_rules(self) -> tuple[Callable[[OnChainBlueprint], None], ...]:
        """Get all rules used in code verification."""
        return (
            self._verify_raw_text,
            self._verify_python_script,
            self._verify_script_restrictions,
            self._verify_has_blueprint_attr,
            self._verify_blueprint_type,
        )

    def verify_code(self, tx: OnChainBlueprint) -> None:
        """Run all verification related to the blueprint code."""
        for rule in self.blueprint_code_rules():
            try:
                rule(tx)
            except SyntaxError as e:
                raise OCBInvalidScript('forbidden syntax') from e

    def _verify_python_script(self, tx: OnChainBlueprint) -> None:
        """Verify that the script can be parsed at all."""
        try:
            self._get_python_code_ast(tx)
        except SyntaxError as e:
            raise OCBInvalidScript('Could not correctly parse the script') from e

    def _verify_raw_text(self, tx: OnChainBlueprint) -> None:
        """Verify that the script does not use any forbidden text."""
        if '__' in tx.code.text:
            raise SyntaxError('script contains dunder text')

    def _verify_script_restrictions(self, tx: OnChainBlueprint) -> None:
        """Verify that the script does not use any forbidden syntax."""
        _RestrictionsVisitor().visit(self._get_python_code_ast(tx))

    def _verify_has_blueprint_attr(self, tx: OnChainBlueprint) -> None:
        """Verify that the script seemingly exports a blueprint."""
        blueprint_ast = self._get_python_code_ast(tx)
        search_decorator = _SearchDecorator('export')
        search_decorator.visit(blueprint_ast)
        if not search_decorator.found:
            raise OCBInvalidScript('Could not find a main Blueprint definition')

    def _verify_blueprint_type(self, tx: OnChainBlueprint) -> None:
        """Verify that the exported blueprint is a Blueprint, this will load and execute the code."""
        from hathor.nanocontracts.blueprint import Blueprint
        blueprint_class = tx.get_blueprint_object_bypass()
        if not isinstance(blueprint_class, type):
            raise OCBInvalidScript('exported Blueprint is not a class')
        if not issubclass(blueprint_class, Blueprint):
            raise OCBInvalidScript('exported Blueprint is not a Blueprint subclass')
