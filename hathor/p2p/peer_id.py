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
    """ Identify a peer, even when it is disconnected.

    The public_key and private_key are used to ensure that a new connection
    that claims to be this peer is really from this peer.

    The entrypoints are strings that describe a way to connect to this peer.
    Usually a peer will have only one entrypoint.
    """
    def __init__(self, auto_generate_keys=True):
        self.id = None
        self.private_key = None
        self.public_key = None
        self.entrypoints = []

        if auto_generate_keys:
            self.generate_keys()

    def merge(self, other):
        """ Merge two PeerId objects, checking that they have the same
        id, public_key, and private_key. The entrypoints are merged without
        duplicating their entries.
        """
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
        """ Generate a random pair of private key and public key.
        It also calculates the id of this peer, based on its public key.
        """
        # https://security.stackexchange.com/questions/5096/rsa-vs-dsa-for-ssh-authentication-keys
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        self.id = self.calculate_id()

    def calculate_id(self):
        """ Calculate and return the id based on the public key.
        """
        public_der = self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        h1 = hashlib.sha256(public_der)
        h2 = hashlib.sha256(h1.digest())
        return h2.hexdigest()

    def get_public_key(self):
        """ Return the public key in DER encoding as an `str`.
        """
        public_der = self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return base64.b64encode(public_der).decode('utf-8')

    def sign(self, data):
        """ Sign any data (of type `bytes`).
        """
        return self.private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    def verify_signature(self, signature, data):
        """ Verify a signature of a data. Both must be of type `bytes`.
        """
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
        """ Create a new PeerId from a JSON.

        It is used both to load a PeerId from disk and to create a PeerId
        from a peer connection.
        """
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
        """ Return `True` if the following conditions are valid:
          (i) public key and private key matches;
         (ii) the id matches with the public key.
        """
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
        """ Return a JSON serialization of the object.

        By default, it will not include the private key. If you would like to add
        it, use the parameter `include_private_key`.
        """
        public_der = self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # This format is compatible with libp2p.
        result = {
            'id': self.id,
            'pubKey': base64.b64encode(public_der).decode('utf-8'),
            'entrypoints': self.entrypoints,
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
        """ Save the object to a JSON file.
        """
        data = self.to_json(include_private_key=True)
        fp = open(path, 'w')
        json.dump(data, fp, indent=4)
        fp.close()
