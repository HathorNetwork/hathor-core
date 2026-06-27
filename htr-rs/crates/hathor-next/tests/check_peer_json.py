# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from sys import stdin
from json import load
from base64 import b64decode
from hashlib import sha256
from cryptography.hazmat.primitives.serialization import load_der_private_key, load_der_public_key, Encoding, PublicFormat

peer_json = load(stdin)
key = load_der_private_key(b64decode(peer_json['privKey']), password=None)
assert key.public_key() == load_der_public_key(b64decode(peer_json['pubKey'])), 'pubkey mismatch'
assert peer_json['id'] == sha256(sha256(key.public_key().public_bytes(encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo)).digest()).hexdigest(), 'peer-id mismatch'

print('all good')
