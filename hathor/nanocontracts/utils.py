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

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from pycoin.key.Key import Key as PycoinKey

from hathor.crypto.util import (
    decode_address,
    get_address_from_public_key_bytes,
    get_public_key_bytes_compressed,
)
from hathor.transaction.headers import NanoHeader
from hathor.util import not_none
from hathorlib.nanocontracts.utils import (  # noqa: F401
    CHILD_CONTRACT_ID_PREFIX,
    CHILD_TOKEN_ID_PREFIX,
    derive_child_contract_id,
    derive_child_token_id,
    is_nc_fallback_method,
    is_nc_public_method,
    is_nc_view_method,
    json_dumps,
    sha3,
    verify_ecdsa,
)


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
    res = code_text.getvalue()
    code_text.close()
    return res


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
