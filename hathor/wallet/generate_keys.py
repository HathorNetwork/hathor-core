from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import json
import base64


def generate_keys(filename):
    keys = {}
    # Private key
    private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
    serialized_key = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    keys['private_key'] = base64.b64encode(serialized_key).decode('utf-8')

    # Public key
    public_key = private_key.public_key()
    serialized_key = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    keys['public_key'] = base64.b64encode(serialized_key).decode('utf-8')

    with open(filename, 'w') as key_file:
        key_file.write(json.dumps(keys, indent=4))

    return private_key, public_key


def load_keys(filename):
    # TODO handle file not existing
    # TODO handle data is not json
    # TODO handle data is not public/private key
    with open(filename, 'r') as key_file:
        keys = json.loads(key_file.read())

    serialized_private = base64.b64decode(keys['private_key'])
    private_key = serialization.load_der_private_key(
        serialized_private,
        password=None,
        backend=default_backend()
    )

    serialized_public = base64.b64decode(keys['public_key'])
    public_key = serialization.load_der_public_key(
        serialized_public,
        backend=default_backend()
    )

    return private_key, public_key
