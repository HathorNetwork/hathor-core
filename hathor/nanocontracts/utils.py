# Copyright 2021 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

import hashlib
from types import ModuleType
from typing import Callable, assert_never

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from pycoin.key.Key import Key as PycoinKey

from hathor.conf.settings import HathorSettings, NanoContractsSetting
from hathor.crypto.util import decode_address, get_address_from_public_key_bytes, get_public_key_bytes_compressed
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.feature_service import FeatureService
from hathor.nanocontracts.types import NC_METHOD_TYPE_ATTR, BlueprintId, ContractId, NCMethodType, TokenUid, VertexId
from hathor.transaction import Vertex
from hathor.transaction.headers import NanoHeader
from hathor.util import not_none

CHILD_CONTRACT_ID_PREFIX: bytes = b'child-contract'
CHILD_TOKEN_ID_PREFIX: bytes = b'child-token'


def is_nc_public_method(method: Callable) -> bool:
    """Return True if the method is nc_public."""
    return getattr(method, NC_METHOD_TYPE_ATTR, None) is NCMethodType.PUBLIC


def is_nc_view_method(method: Callable) -> bool:
    """Return True if the method is nc_view."""
    return getattr(method, NC_METHOD_TYPE_ATTR, None) is NCMethodType.VIEW


def is_nc_fallback_method(method: Callable) -> bool:
    """Return True if the method is nc_fallback."""
    return getattr(method, NC_METHOD_TYPE_ATTR, None) is NCMethodType.FALLBACK


def load_builtin_blueprint_for_ocb(filename: str, blueprint_name: str, module: ModuleType | None = None) -> str:
    """Get blueprint code from a file."""
    import io
    import os

    from hathor.nanocontracts import blueprints

    module = module or blueprints
    cur_dir = os.path.dirname(not_none(module.__file__))
    filepath = os.path.join(not_none(cur_dir), filename)
    code_text = io.StringIO()
    with open(filepath, 'r') as nc_file:
        for line in nc_file.readlines():
            code_text.write(line)
    code_text.write(f'__blueprint__ = {blueprint_name}\n')
    res = code_text.getvalue()
    code_text.close()
    return res


def derive_child_contract_id(parent_id: ContractId, salt: bytes, blueprint_id: BlueprintId) -> ContractId:
    """Derives the contract id for a nano contract created by another (parent) contract."""
    h = hashlib.sha256()
    h.update(CHILD_CONTRACT_ID_PREFIX)
    h.update(parent_id)
    h.update(salt)
    h.update(blueprint_id)
    return ContractId(VertexId(h.digest()))


def derive_child_token_id(parent_id: ContractId, token_symbol: str) -> TokenUid:
    """Derive the token id for a token created by a (parent) contract."""
    h = hashlib.sha256()
    h.update(CHILD_TOKEN_ID_PREFIX)
    h.update(parent_id)
    h.update(token_symbol.encode('utf-8'))
    return TokenUid(VertexId(h.digest()))


def sign_openssl(nano_header: NanoHeader, privkey: ec.EllipticCurvePrivateKey) -> None:
    """Sign this nano header using a privkey from the cryptography lib."""
    from hathor.transaction import Transaction
    from hathor.transaction.scripts import P2PKH

    pubkey = privkey.public_key()
    pubkey_bytes = get_public_key_bytes_compressed(pubkey)
    nano_header.nc_address = get_address_from_public_key_bytes(pubkey_bytes)

    assert isinstance(nano_header.tx, Transaction)
    data = nano_header.tx.get_sighash_all_data()
    signature = privkey.sign(data, ec.ECDSA(hashes.SHA256()))

    nano_header.nc_script = P2PKH.create_input_data(public_key_bytes=pubkey_bytes, signature=signature)


def sign_pycoin(nano_header: NanoHeader, privkey: PycoinKey) -> None:
    """Sign this nano header using a privkey from the pycoin lib."""
    from hathor.transaction import Transaction
    from hathor.transaction.scripts import P2PKH

    pubkey_bytes = privkey.sec()
    nano_header.nc_address = get_address_from_public_key_bytes(pubkey_bytes)

    assert isinstance(nano_header.tx, Transaction)
    data = nano_header.tx.get_sighash_all_data()
    data_hash = hashlib.sha256(data).digest()
    signature = privkey.sign(data_hash)

    nano_header.nc_script = P2PKH.create_input_data(public_key_bytes=pubkey_bytes, signature=signature)


def sign_openssl_multisig(
    nano_header: NanoHeader,
    *,
    required_count: int,
    redeem_pubkey_bytes: list[bytes],
    sign_privkeys: list[ec.EllipticCurvePrivateKey],
) -> None:
    """Sign this nano header with multisig using privkeys from the cryptography lib."""
    from hathor.transaction import Transaction
    from hathor.transaction.scripts import MultiSig
    from hathor.wallet.util import generate_multisig_address, generate_multisig_redeem_script

    redeem_script = generate_multisig_redeem_script(required_count, redeem_pubkey_bytes)
    multisig_address_b58 = generate_multisig_address(redeem_script)
    multisig_address = decode_address(multisig_address_b58)
    nano_header.nc_address = multisig_address

    assert isinstance(nano_header.tx, Transaction)
    data = nano_header.tx.get_sighash_all_data()
    signatures = [privkey.sign(data, ec.ECDSA(hashes.SHA256())) for privkey in sign_privkeys]

    nano_header.nc_script = MultiSig.create_input_data(redeem_script, signatures)


def is_nano_active(settings: HathorSettings, vertex: Vertex, feature_service: FeatureService) -> bool:
    """Return whether the Nano Contracts feature is active according to the provided settings and vertex."""
    match settings.ENABLE_NANO_CONTRACTS:
        case NanoContractsSetting.DISABLED:
            return False
        case NanoContractsSetting.ENABLED:
            return True
        case NanoContractsSetting.FEATURE_ACTIVATION:
            return feature_service.is_feature_active(vertex=vertex, feature=Feature.NANO_CONTRACTS)
        case _:  # pragma: no cover
            assert_never(settings.ENABLE_NANO_CONTRACTS)
