import struct
import hashlib
import base58
from hathor.transaction.exceptions import InputSignatureError, InputPublicKeyError
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


# public_key is ec.EllipticCurvePublicKey
def get_public_key_bytes(public_key, encoding=serialization.Encoding.DER,
                         format=serialization.PublicFormat.SubjectPublicKeyInfo):
    return public_key.public_bytes(
        encoding,
        format
    )


def get_public_key_from_bytes(public_key_bytes, backend=default_backend()):
    return serialization.load_der_public_key(public_key_bytes, backend)


# private_key is ec.EllipticCurvePrivateKey
# data_to_sign is bytes
def sign_data(private_key, data_to_sign, sig_algorithm=ec.ECDSA(hashes.SHA256())):
    return private_key.sign(data_to_sign, sig_algorithm)


# TODO secp256k1 public keys generated with cryptography are
# not 32/33 bytes long as expected. We'd have to manually convert
# the public numbers to get it
def get_address_from_public_key(public_key):
    key_hash = hashlib.sha256(public_key)
    h = hashlib.new('ripemd160')
    h.update(key_hash.digest())
    return h.digest()


def get_address_human_readable(public_key):
    return base58.b58encode(get_address_from_public_key(public_key))


# private_key is ec.EllipticCurvePrivateKey
# public_key is ec.EllipticCurvePublicKey
def get_input_data(data_to_sign, private_key, public_key):
    signature = sign_data(private_key, data_to_sign)
    public_key_bytes = get_public_key_bytes(public_key)
    format_str = 'B%dsB%ds' % (len(signature), len(public_key_bytes))
    return struct.pack(
        format_str,
        len(signature),
        signature,
        len(public_key_bytes),
        public_key_bytes
    )


def validate_signature(input_data, original_data):
    (_, signature, _, public_key_bytes) = decode_input_data(input_data)
    public_key = get_public_key_from_bytes(public_key_bytes)
    try:
        public_key.verify(signature, original_data, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise InputSignatureError


def validate_script(input_data, script):
    (_, _, _, public_key_bytes) = decode_input_data(input_data)
    # script is just address
    if get_address_from_public_key(public_key_bytes) != script:
        raise InputPublicKeyError


def decode_input_data(input_data):
    # data is (signature_len, signature, public_key_len, public_key)
    signature_len = input_data[0]
    public_key_len = len(input_data) - signature_len - 2
    format_str = 'B%dsB%ds' % (signature_len, public_key_len)
    return struct.unpack(format_str, input_data)
