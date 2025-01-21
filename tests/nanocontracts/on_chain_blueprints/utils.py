from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from hathor.crypto.util import get_public_key_bytes_compressed
from hathor.nanocontracts import OnChainBlueprint
from hathor.wallet import KeyPair
from tests import unittest


def load_bultin_nc_code(filename: str, blueprint_name: str) -> str:
    import io
    import os

    from hathor.nanocontracts import blueprints
    cur_dir = os.path.dirname(blueprints.__file__)
    filepath = os.path.join(cur_dir, filename)
    code_text = io.StringIO()
    with open(filepath, 'r') as nc_file:
        for line in nc_file.readlines():
            code_text.write(line)
    code_text.write(f'__blueprint__ = {blueprint_name}\n')
    res = code_text.getvalue()
    code_text.close()
    return res


def ocb_sign(blueprint: OnChainBlueprint) -> None:
    key = KeyPair(unittest.OCB_TEST_PRIVKEY)
    privkey = key.get_private_key(unittest.OCB_TEST_PASSWORD)
    pubkey = privkey.public_key()
    blueprint.nc_pubkey = get_public_key_bytes_compressed(pubkey)
    data = blueprint.get_sighash_all_data()
    blueprint.nc_signature = privkey.sign(data, ec.ECDSA(hashes.SHA256()))
