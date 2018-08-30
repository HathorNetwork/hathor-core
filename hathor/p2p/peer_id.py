# encoding: utf-8

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

import hashlib
import base64
import json


class InvalidPeerIdException(Exception):
    pass


class PeerId(object):
    def __init__(self, auto_generate_keys=True):
        self.id = None
        self.private_key = None
        self.public_key = None
        self.entrypoints = []

        if auto_generate_keys:
            self.generate_keys()

    def merge(self, other):
        assert(self.id == other.id)

        # Copy public key if `self` doesn't have it and `other` does.
        if not self.public_key and other.public_key:
            self.public_key = other.public_key
            self.validate()

        if self.public_key and other.public_key:
            assert(self.get_public_key() == other.get_public_key())

        # Copy private key if `self` doesn't have it and `other` does.
        if not self.private_key and other.private_key:
            self.private_key = other.private_key
            self.validate()

        # Merge entrypoints.
        for ep in other.entrypoints:
            if ep not in self.entrypoints:
                self.entrypoints.append(ep)

    def generate_keys(self, key_size=2048):
        # https://security.stackexchange.com/questions/5096/rsa-vs-dsa-for-ssh-authentication-keys
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        self.id = self.calculate_id()

    def calculate_id(self):
        public_der = self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        h1 = hashlib.sha256(public_der)
        h2 = hashlib.sha256(h1.digest())
        return h2.hexdigest()

    def get_public_key(self):
        public_der = self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return base64.b64encode(public_der).decode('utf-8')

    def sign(self, data):
        return self.private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    def verify_signature(self, signature, data):
        try:
            self.public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except InvalidSignature:
            return False
        else:
            return True

    @classmethod
    def create_from_json(cls, data):
        obj = cls(auto_generate_keys=False)
        obj.id = data['id']

        if 'pubKey' in data:
            public_key_der = base64.b64decode(data['pubKey'])
            obj.public_key = serialization.load_der_public_key(
                data=public_key_der,
                backend=default_backend()
            )

        if 'privKey' in data:
            private_key_der = base64.b64decode(data['privKey'])
            obj.private_key = serialization.load_der_private_key(
                data=private_key_der,
                password=None,
                backend=default_backend()
            )

        if 'entrypoints' in data:
            obj.entrypoints = data['entrypoints']

        return obj

    def validate(self):
        if self.private_key and not self.public_key:
            self.public_key = self.private_key.public_key()

        if self.public_key:
            if self.id != self.calculate_id():
                raise InvalidPeerIdException('id does not match public key')

        if self.private_key:
            public_der1 = self.public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            public_key = self.private_key.public_key()
            public_der2 = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            if public_der1 != public_der2:
                raise InvalidPeerIdException('private/public pair does not match')

    def to_json(self, include_private_key=False):
        public_der = self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # This format is compatible with libp2p.
        result = {
            'id': self.id,
            'pubKey': base64.b64encode(public_der).decode('utf-8'),
        }
        if include_private_key:
            private_der = self.private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                # TODO encryption_algorithm=serialization.BestAvailableEncryption(b'mypassword')
                encryption_algorithm=serialization.NoEncryption()
            )
            result['privKey'] = base64.b64encode(private_der).decode('utf-8')

        return result

    def save_to_file(self, path):
        data = self.to_json(include_private_key=True)
        fp = open(path, 'w')
        json.dump(data, fp, indent=4)
        fp.close()
