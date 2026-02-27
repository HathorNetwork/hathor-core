# Copyright 2024 Hathor Labs
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

"""ECDH key exchange and nonce derivation for shielded output recovery.

Uses secp256k1 via the `cryptography` library (already a project dependency).
"""

import hashlib

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

_NONCE_DOMAIN_SEPARATOR = b'Hathor_CT_nonce_v1'


def generate_ephemeral_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh ephemeral secp256k1 key pair.

    Returns:
        (private_key_bytes: 32B, compressed_pubkey_bytes: 33B)
    """
    private_key = ec.generate_private_key(ec.SECP256K1())
    privkey_bytes = private_key.private_numbers().private_value.to_bytes(32, 'big')  # type: ignore[attr-defined]
    pubkey_bytes = private_key.public_key().public_bytes(
        encoding=Encoding.X962,
        format=PublicFormat.CompressedPoint,
    )
    return privkey_bytes, pubkey_bytes


def derive_ecdh_shared_secret(private_key_bytes: bytes, peer_pubkey_bytes: bytes) -> bytes:
    """Compute ECDH shared secret: SHA256(private_key * peer_pubkey).

    Args:
        private_key_bytes: 32-byte private scalar
        peer_pubkey_bytes: 33-byte compressed public key

    Returns:
        32-byte shared secret
    """
    # Load private key
    private_value = int.from_bytes(private_key_bytes, 'big')
    private_key = ec.derive_private_key(private_value, ec.SECP256K1())

    # Load peer public key
    peer_pubkey = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), peer_pubkey_bytes)

    # ECDH: compute raw shared point
    shared_key = private_key.exchange(ec.ECDH(), peer_pubkey)

    # Hash the raw shared secret for uniformity
    return hashlib.sha256(shared_key).digest()


def derive_rewind_nonce(shared_secret: bytes) -> bytes:
    """Derive a deterministic nonce from a shared secret.

    nonce = SHA256("Hathor_CT_nonce_v1" || shared_secret)

    Args:
        shared_secret: 32-byte ECDH shared secret

    Returns:
        32-byte nonce suitable for use as a range proof nonce key
    """
    return hashlib.sha256(_NONCE_DOMAIN_SEPARATOR + shared_secret).digest()


def extract_key_bytes(key: object) -> tuple[bytes, bytes]:
    """Extract (private_key_bytes, compressed_pubkey_bytes) from a wallet key.

    Handles both key types used in the wallet:
    - `cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey`
      (from Wallet.get_private_key())
    - pycoin `Key` (from HDWallet.get_private_key())

    Returns:
        (private_key_bytes: 32B, compressed_pubkey_bytes: 33B)
    """
    if isinstance(key, ec.EllipticCurvePrivateKey):
        privkey_bytes = key.private_numbers().private_value.to_bytes(32, 'big')  # type: ignore[attr-defined]
        pubkey_bytes = key.public_key().public_bytes(
            encoding=Encoding.X962,
            format=PublicFormat.CompressedPoint,
        )
        return privkey_bytes, pubkey_bytes

    # pycoin Key — has .secret_exponent() and .sec()
    if hasattr(key, 'secret_exponent') and hasattr(key, 'sec'):
        secret_exp = key.secret_exponent()
        privkey_bytes = secret_exp.to_bytes(32, 'big')
        pubkey_bytes = key.sec(is_compressed=True)
        return privkey_bytes, pubkey_bytes

    raise TypeError(f'unsupported key type: {type(key).__name__}')
