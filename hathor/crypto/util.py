import hashlib
import base58
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from hathor.constants import P2PKH_VERSION_BYTE, MULTISIG_VERSION_BYTE


def get_private_key_bytes(private_key,
                          encoding=serialization.Encoding.DER,
                          format=serialization.PrivateFormat.PKCS8,
                          encryption_algorithm=serialization.NoEncryption()):
    return private_key.private_bytes(
        encoding=encoding,
        format=format,
        encryption_algorithm=encryption_algorithm
    )


def get_private_key_from_bytes(private_key_bytes, password=None, backend=default_backend()):
    """Returns the cryptography ec.EllipticCurvePrivateKey from bytes"""
    return serialization.load_der_private_key(private_key_bytes, password, backend)


def get_public_key_from_bytes(public_key_bytes, backend=default_backend()):
    """Returns the cryptography ec.EllipticCurvePublicKey from bytes"""
    return serialization.load_der_public_key(public_key_bytes, backend)


def get_hash160(public_key_bytes):
    """The input is hashed twice: first with SHA-256 and then with RIPEMD-160

    :type: bytes

    :rtype: bytes
    """
    key_hash = hashlib.sha256(public_key_bytes)
    h = hashlib.new('ripemd160')
    h.update(key_hash.digest())
    return h.digest()


def get_address_from_public_key(public_key):
    """ Get bytes from public key object and call method that expect bytes

        :param public_key: Public key object
        :param public_key: ec.EllipticCurvePublicKey

        :return: address in bytes
        :rtype: bytes
    """
    public_key_bytes = get_public_key_bytes_compressed(public_key)
    return get_address_from_public_key_bytes(public_key_bytes)


def get_address_from_public_key_bytes(public_key_bytes):
    """ Calculate public key hash and get address from it

        :param public_key_bytes: public key in bytes
        :param public_key_bytes: bytes

        :return: address in bytes
        :rtype: bytes
    """
    public_key_hash = get_hash160(public_key_bytes)
    return get_address_from_public_key_hash(public_key_hash)


def get_address_b58_from_public_key(public_key):
    """Gets the b58 address from a public key.

    :param: ec.EllipticCurvePublicKey
    :return: the b58-encoded address
    :rtype: string
    """
    public_key_bytes = get_public_key_bytes_compressed(public_key)
    return get_address_b58_from_public_key_bytes(public_key_bytes)


def get_address_b58_from_public_key_hash(public_key_hash):
    """Gets the b58 address from the hash of a public key.

        :param public_key_hash: hash of public key (sha256 and ripemd160)
        :param public_key_hash: bytes

        :return: address in base 58
        :rtype: string
    """
    address = get_address_from_public_key_hash(public_key_hash)
    return base58.b58encode(address).decode('utf-8')


def get_address_from_public_key_hash(public_key_hash, version_byte=P2PKH_VERSION_BYTE):
    """Gets the address in bytes from the public key hash

        :param public_key_hash: hash of public key (sha256 and ripemd160)
        :param public_key_hash: bytes

        :param version_byte: first byte of address to define the version of this address
        :param version_byte: bytes

        :return: address in bytes
        :rtype: bytes
    """
    address = b''
    # Version byte
    address += version_byte
    # Pubkey hash
    address += public_key_hash
    checksum = get_checksum(address)
    address += checksum
    return address


def get_checksum(address_bytes):
    """ Calculate double sha256 of address and gets first 4 bytes

        :param address_bytes: address before checksum
        :param address_bytes: bytes

        :return: checksum of the address
        :rtype: bytes
    """
    return hashlib.sha256(hashlib.sha256(address_bytes).digest()).digest()[:4]


def get_address_b58_from_public_key_bytes(public_key_bytes):
    """Gets the b58 address from a public key bytes.

        :param public_key_bytes: public key in bytes
        :param public_key_bytes: bytes

        :return: address in base 58
        :rtype: string
    """
    public_key_hash = get_hash160(public_key_bytes)
    return get_address_b58_from_public_key_hash(public_key_hash)


def get_address_b58_from_bytes(address):
    """Gets the b58 address from the address in bytes

        :param address: bytes

        :return: address in base 58
        :rtype: string
    """
    return base58.b58encode(address).decode('utf-8')


def generate_privkey_crt_pem():
    """ Generates a new certificate with a new private key. This certificate is
    used only for TLS connection, and won't be used to identify the peer.

    Adapted from:
    https://github.com/twisted/twisted/blob/trunk/src/twisted/test/server.pem

    :return: Private key and certificate in PEM format
    :rtype: string
    """
    from datetime import datetime

    from OpenSSL.crypto import FILETYPE_PEM, TYPE_RSA, X509, PKey, dump_privatekey, dump_certificate

    key = PKey()
    key.generate_key(TYPE_RSA, 2048)

    cert = X509()

    # It is optional to have a subject and an issue in a certificate.
    # It works with and without these fields.
    # issuer = cert.get_issuer()
    # subject = cert.get_subject()
    # for dn in [issuer, subject]:
    #     dn.C = b'XX'   # Country
    #     dn.ST = b'XX'  # State or Province
    #     dn.L = b'XX'   # Locality
    #     dn.CN = b'testnet.hathor.network'  # Common Name
    #     dn.O = b'Hathor Network'  # noqa: E741 ambiguous variable name 'O'
    #     dn.OU = b'testnet'   # Organization Unit
    #     dn.emailAddress = b'noreply@testnet.hathor.network'

    # Set the period in which the certificate is valid. In this case, the
    # reference time is now, and it will be valid between 10 minutes ago
    # and 100 years from now. This 10 minutes tolerance is to accomodate
    # differences in the time between peers.
    # To check the valid period, run a server with ssl and then run:
    # `openssl s_client -showcerts -connect localhost:8000 | openssl x509 -noout -dates`
    cert.set_serial_number(datetime.now().toordinal())
    cert.gmtime_adj_notBefore(-60 * 10)
    cert.gmtime_adj_notAfter(60 * 60 * 24 * 365 * 100)

    cert.set_pubkey(key)
    cert.sign(key, 'sha256')
    return dump_privatekey(FILETYPE_PEM, key) + dump_certificate(FILETYPE_PEM, cert)


def get_public_key_bytes_compressed(public_key):
    """ Returns the bytes from a cryptography ec.EllipticCurvePublicKey in a compressed format

        :param public_key: Public key object
        :type public_key: ec.EllipticCurvePublicKey

        :rtype: bytes
    """
    pn = public_key.public_numbers()
    return pn.encode_point(compressed=True)


def get_public_key_from_bytes_compressed(public_key_bytes, backend=default_backend()):
    """ Returns the cryptography public key from the compressed bytes format

        :param public_key_bytes: Compressed format of public key in bytes
        :type public_key_bytes: bytes

        :rtype: ec.EllipticCurvePublicKey
    """
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), public_key_bytes, backend)


def get_address_b58_from_redeem_script_hash(redeem_script_hash, version_byte=MULTISIG_VERSION_BYTE):
    """Gets the b58 address from the hash of the redeem script in multisig.

        :param redeem_script_hash: hash of the redeem script (sha256 and ripemd160)
        :param redeem_script_hash: bytes

        :return: address in base 58
        :rtype: string
    """
    address = get_address_from_redeem_script_hash(redeem_script_hash, version_byte)
    return base58.b58encode(address).decode('utf-8')


def get_address_from_redeem_script_hash(redeem_script_hash, version_byte=MULTISIG_VERSION_BYTE):
    """Gets the address in bytes from the redeem script hash

        :param redeem_script_hash: hash of redeem script (sha256 and ripemd160)
        :param redeem_script_hash: bytes

        :param version_byte: first byte of address to define the version of this address
        :param version_byte: bytes

        :return: address in bytes
        :rtype: bytes
    """
    address = b''
    # Version byte
    address += version_byte
    # redeem script hash
    address += redeem_script_hash
    checksum = get_checksum(address)
    address += checksum
    return address
