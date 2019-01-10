import argparse
import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

from hathor.crypto.util import get_hash160, get_private_key_bytes, get_public_key_bytes_compressed


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument('filepath', help='Create a new private key in the given file')
    args = parser.parse_args()

    new_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
    private_key_bytes = get_private_key_bytes(new_key)
    with open(args.filepath, 'w') as key_file:
        key_file.write(base64.b64encode(private_key_bytes).decode('utf-8'))
        print('key created!')
    public_key_bytes = get_public_key_bytes_compressed(new_key.public_key())
    print('base64 pubkey hash:', base64.b64encode(get_hash160(public_key_bytes)).decode('utf-8'))
