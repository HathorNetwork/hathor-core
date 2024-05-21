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

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from hathor.conf.settings import HathorSettings
from hathor.crypto.util import get_address_b58_from_public_key_bytes, get_public_key_from_bytes_compressed
from hathor.nanocontracts import OnChainBlueprint
from hathor.nanocontracts.exception import NCInvalidPubKey, NCInvalidSignature, OCBInvalidScript, OCBPubKeyNotAllowed
from hathor.nanocontracts.on_chain_blueprint import BLUEPRINT_CLASS_NAME

ALLOWED_IMPORTS = {
    # globals
    'math': {'ceil', 'floor'},
    'typing': {'Optional', 'NamedTuple', 'TypeAlias'},
    # hathor
    'hathor.nanocontracts': {'Blueprint'},
    'hathor.nanocontracts.blueprint': {'Blueprint'},
    'hathor.nanocontracts.context': {'Context'},
    'hathor.nanocontracts.exception': {'NCFail'},
    'hathor.nanocontracts.types': {'NCAction', 'NCActionType', 'SignedData', 'public', 'view', 'Address', 'Amount',
                                   'Timestamp', 'TokenUid', 'TxOutputScript', 'BlueprintId', 'ContractId', 'VertexId'},
}

NAME_BLACKLIST = {
    '__builtins__',
    '__import__',
    'compile',
    'delattr',
    'dir',
    'eval',
    'exec',
    'getattr',
    'globals',
    'hasattr',
    'input',
    'locals',
    'open',
    'setattr',
    'vars',
}


class _RestrictionsVisitor(ast.NodeVisitor):
    def visit_Import(self, node: ast.Import) -> None:
        raise SyntaxError('Import statements are not allowed.')

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module not in ALLOWED_IMPORTS:
            raise SyntaxError(f'Import from "{node.module}" is not allowed.')
        allowed_aliases = ALLOWED_IMPORTS[node.module]
        for alias in node.names:
            if alias.name not in allowed_aliases:
                raise SyntaxError(f'Import from "{node.module}.{alias.name}" is not allowed.')

    def visit_Try(self, node: ast.Try) -> None:
        raise SyntaxError('Try/Except blocks are not allowed.')

    def visit_Name(self, node: ast.Name) -> None:
        if node.id in NAME_BLACKLIST:
            raise SyntaxError(f'Usage or reference to {node.id} is not allowed.')
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if isinstance(node.value, ast.Name):
            if node.attr.startswith('__'):
                raise SyntaxError('Access to internal attributes and methods is not allowed.')
        self.generic_visit(node)


class _SearchName(ast.NodeVisitor):
    def __init__(self, name: str) -> None:
        self.search_name = name
        self.found = False

    def visit_Name(self, node: ast.Name) -> None:
        if node.id == self.search_name:
            self.found = True
            return
        self.generic_visit(node)


class OnChainBlueprintVerifier:
    __slots__ = ('_settings',)

    def __init__(self, *, settings: HathorSettings):
        self._settings = settings

    def verify_pubkey_is_allowed(self, tx: OnChainBlueprint) -> None:
        """Verify if the on-chain blueprint's pubkey is allowed."""
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

    def verify_script_restrictions(self, tx: OnChainBlueprint) -> None:
        """Verify that the script does not use any forbidden syntax."""
        parsed_tree = ast.parse(tx.code.text())
        restrictions_visitor = _RestrictionsVisitor()
        try:
            restrictions_visitor.visit(parsed_tree)
        except SyntaxError as e:
            raise OCBInvalidScript from e

    def verify_has_blueprint_object(self, tx: OnChainBlueprint) -> None:
        parsed_tree = ast.parse(tx.code.text())
        search_name = _SearchName(BLUEPRINT_CLASS_NAME)
        search_name.visit(parsed_tree)
        if not search_name.found:
            raise OCBInvalidScript(f'Could not find {BLUEPRINT_CLASS_NAME} object')
