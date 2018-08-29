# encoding: utf-8

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

import hashlib
import base64
import json


class PeerId(object):
    def __init__(self, auto_generate_keys=True):
        self.id = None
        self.private_key = None
        self.public_key = None
        self.endpoints = []

        if auto_generate_keys:
            self.generate_keys()

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

    @classmethod
    def create_from_json(cls, data):
        # TODO Check whether pubkey, privkey, and id match.
        obj = cls(auto_generate_keys=False)
        obj.id = data['id']

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

        self.validate()
        return obj

    def validate(self):
        pass

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
