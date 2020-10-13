import base64
import hashlib
import json
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, Generator, List, Optional, Set

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from OpenSSL.crypto import X509, PKey
from twisted.internet.defer import inlineCallbacks
from twisted.internet.ssl import Certificate, CertificateOptions, TLSVersion, trustRootFromCertificates

from hathor.conf import HathorSettings
from hathor.p2p.utils import connection_string_to_host, discover_dns, generate_certificate

if TYPE_CHECKING:
    from hathor.p2p.protocol import HathorProtocol  # noqa: F401

settings = HathorSettings()


class InvalidPeerIdException(Exception):
    pass


class PeerFlags(str, Enum):
    RETRIES_EXCEEDED = 'retries_exceeded'


class PeerId:
    """ Identify a peer, even when it is disconnected.

    The public_key and private_key are used to ensure that a new connection
    that claims to be this peer is really from this peer.

    The entrypoints are strings that describe a way to connect to this peer.
    Usually a peer will have only one entrypoint.
    """

    id: Optional[str]
    entrypoints: List[str]
    private_key: Optional[rsa.RSAPrivateKeyWithSerialization]
    public_key: Optional[rsa.RSAPublicKey]
    certificate: Optional[x509.Certificate]
    retry_timestamp: int    # should only try connecting to this peer after this timestamp
    retry_interval: int     # how long to wait for next connection retry. It will double for each failure
    retry_attempts: int     # how many retries were made
    flags: Set[str]

    def __init__(self, auto_generate_keys: bool = True) -> None:
        self.id = None
        self.private_key = None
        self.public_key = None
        self.certificate = None
        self.entrypoints = []
        self.retry_timestamp = 0
        self.retry_interval = 5
        self.retry_attempts = 0
        self.flags = set()

        if auto_generate_keys:
            self.generate_keys()

    def __str__(self):
        return ('PeerId(id=%s, entrypoints=%s, retry_timestamp=%d, retry_interval=%d)' % (self.id, self.entrypoints,
                self.retry_timestamp, self.retry_interval))

    def merge(self, other: 'PeerId') -> None:
        """ Merge two PeerId objects, checking that they have the same
        id, public_key, and private_key. The entrypoints are merged without
        duplicating their entries.
        """
        assert (self.id == other.id)

        # Copy public key if `self` doesn't have it and `other` does.
        if not self.public_key and other.public_key:
            self.public_key = other.public_key
            self.validate()

        if self.public_key and other.public_key:
            assert (self.get_public_key() == other.get_public_key())

        # Copy private key if `self` doesn't have it and `other` does.
        if not self.private_key and other.private_key:
            self.private_key = other.private_key
            self.validate()

        # Merge entrypoints.
        for ep in other.entrypoints:
            if ep not in self.entrypoints:
                self.entrypoints.append(ep)

    def generate_keys(self, key_size: int = 2048) -> None:
        """ Generate a random pair of private key and public key.
        It also calculates the id of this peer, based on its public key.
        """
        # https://security.stackexchange.com/questions/5096/rsa-vs-dsa-for-ssh-authentication-keys
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size,
                                                    backend=default_backend())
        self.public_key = self.private_key.public_key()
        self.id = self.calculate_id()

    def calculate_id(self) -> str:
        """ Calculate and return the id based on the public key.
        """
        assert self.public_key is not None
        public_der = self.public_key.public_bytes(encoding=serialization.Encoding.DER,
                                                  format=serialization.PublicFormat.SubjectPublicKeyInfo)
        h1 = hashlib.sha256(public_der)
        h2 = hashlib.sha256(h1.digest())
        return h2.hexdigest()

    def get_public_key(self) -> str:
        """ Return the public key in DER encoding as an `str`.
        """
        assert self.public_key is not None
        public_der = self.public_key.public_bytes(encoding=serialization.Encoding.DER,
                                                  format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return base64.b64encode(public_der).decode('utf-8')

    def sign(self, data: bytes) -> bytes:
        """ Sign any data (of type `bytes`).
        """
        assert self.private_key is not None
        return self.private_key.sign(
            data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

    def verify_signature(self, signature: bytes, data: bytes) -> bool:
        """ Verify a signature of a data. Both must be of type `bytes`.
        """
        try:
            assert self.public_key is not None
            self.public_key.verify(signature, data,
                                   padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                                   hashes.SHA256())
        except InvalidSignature:
            return False
        else:
            return True

    @classmethod
    def create_from_json(cls, data: Dict[str, Any]) -> 'PeerId':
        """ Create a new PeerId from a JSON.

        It is used both to load a PeerId from disk and to create a PeerId
        from a peer connection.
        """
        obj = cls(auto_generate_keys=False)
        obj.id = data['id']

        if 'pubKey' in data:
            public_key_der = base64.b64decode(data['pubKey'])
            obj.public_key = serialization.load_der_public_key(data=public_key_der, backend=default_backend())

        if 'privKey' in data:
            private_key_der = base64.b64decode(data['privKey'])
            obj.private_key = serialization.load_der_private_key(data=private_key_der, password=None,
                                                                 backend=default_backend())

        if 'entrypoints' in data:
            obj.entrypoints = data['entrypoints']

        # TODO(epnichols): call obj.validate()?
        return obj

    def validate(self) -> None:
        """ Return `True` if the following conditions are valid:
          (i) public key and private key matches;
         (ii) the id matches with the public key.

         TODO(epnichols): Update docs.  Only raises exceptions; doesn't return anything.
        """
        if self.private_key and not self.public_key:
            # TODO(epnichols): Modifies self.public_key, even though we're calling "validate". Why is state modified?
            self.public_key = self.private_key.public_key()

        if self.public_key:
            if self.id != self.calculate_id():
                raise InvalidPeerIdException('id does not match public key')

        if self.private_key:
            assert self.public_key is not None
            public_der1 = self.public_key.public_bytes(encoding=serialization.Encoding.DER,
                                                       format=serialization.PublicFormat.SubjectPublicKeyInfo)
            public_key = self.private_key.public_key()
            public_der2 = public_key.public_bytes(encoding=serialization.Encoding.DER,
                                                  format=serialization.PublicFormat.SubjectPublicKeyInfo)
            if public_der1 != public_der2:
                raise InvalidPeerIdException('private/public pair does not match')

    def to_json(self, include_private_key: bool = False) -> Dict[str, Any]:
        """ Return a JSON serialization of the object.

        By default, it will not include the private key. If you would like to add
        it, use the parameter `include_private_key`.
        """
        assert self.public_key is not None
        public_der = self.public_key.public_bytes(encoding=serialization.Encoding.DER,
                                                  format=serialization.PublicFormat.SubjectPublicKeyInfo)
        # This format is compatible with libp2p.
        result = {
            'id': self.id,
            'pubKey': base64.b64encode(public_der).decode('utf-8'),
            'entrypoints': self.entrypoints,
        }
        if include_private_key:
            assert self.private_key is not None
            private_der = self.private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                # TODO encryption_algorithm=serialization.BestAvailableEncryption(b'mypassword')
                encryption_algorithm=serialization.NoEncryption())
            result['privKey'] = base64.b64encode(private_der).decode('utf-8')

        return result

    def save_to_file(self, path: str) -> None:
        """ Save the object to a JSON file.
        """
        data = self.to_json(include_private_key=True)
        fp = open(path, 'w')
        json.dump(data, fp, indent=4)
        fp.close()

    def update_retry_timestamp(self, now: int) -> None:
        """ Updates timestamp for next retry.

        :param now: current timestamp
        """
        self.retry_interval = self.retry_interval * settings.PEER_CONNECTION_RETRY_INTERVAL_MULTIPLIER
        if self.retry_interval > 180:
            self.retry_interval = 180
        self.retry_timestamp = now + self.retry_interval

    def reset_retry_timestamp(self) -> None:
        """ Resets retry values.
        """
        self.retry_interval = 5
        self.retry_timestamp = 0
        self.retry_attempts = 0
        self.flags.discard(PeerFlags.RETRIES_EXCEEDED)

    def can_retry(self, now: int) -> bool:
        """ Return if can retry to connect to self in `now` timestamp
            We validate if peer already has RETRIES_EXCEEDED flag, or has reached the maximum allowed attempts
            If not, we check if the timestamp is already a valid one to retry
        """
        if PeerFlags.RETRIES_EXCEEDED in self.flags:
            return False

        if self.retry_attempts >= settings.MAX_PEER_CONNECTION_ATTEMPS:
            self.flags.add(PeerFlags.RETRIES_EXCEEDED)
            return False

        if now >= self.retry_timestamp:
            self.retry_attempts += 1
            return True

        return False

    def get_certificate(self) -> x509.Certificate:
        if not self.certificate:
            certificate = generate_certificate(self.private_key, settings.CA_FILEPATH, settings.CA_KEY_FILEPATH)
            self.certificate = certificate

        return self.certificate

    def get_certificate_options(self) -> CertificateOptions:
        """ Return certificate options
            With certificate generated and signed with peer private key
        """
        certificate = self.get_certificate()
        openssl_certificate = X509.from_cryptography(certificate)
        openssl_pkey = PKey.from_cryptography_key(self.private_key)

        with open(settings.CA_FILEPATH, 'rb') as f:
            ca = x509.load_pem_x509_certificate(data=f.read(), backend=default_backend())

        openssl_ca = X509.from_cryptography(ca)
        ca_cert = Certificate(openssl_ca)
        trust_root = trustRootFromCertificates([ca_cert])

        # We should not use a ContextFactory
        # https://twistedmatrix.com/documents/19.7.0/api/twisted.protocols.tls.TLSMemoryBIOFactory.html
        certificate_options = CertificateOptions(
            privateKey=openssl_pkey,
            certificate=openssl_certificate,
            trustRoot=trust_root,
            raiseMinimumTo=TLSVersion.TLSv1_3
        )
        return certificate_options

    @inlineCallbacks
    def validate_entrypoint(self, protocol: 'HathorProtocol') -> Generator[Any, Any, bool]:
        """ Validates if connection entrypoint is one of the peer entrypoints
        """
        found_entrypoint = False

        # If has no entrypoints must be behind a NAT, so we add the flag to the connection
        if len(self.entrypoints) == 0:
            protocol.warning_flags.add(protocol.WarningFlags.NO_ENTRYPOINTS)
            # If there are no entrypoints, we don't need to validate it
            found_entrypoint = True

        # Entrypoint validation with connection string and connection host
        # Entrypoints have the format tcp://IP|name:port
        for entrypoint in self.entrypoints:
            if protocol.connection_string:
                # Connection string has the format tcp://IP:port
                # So we must consider that the entrypoint could be in name format
                if protocol.connection_string == entrypoint:
                    # Found the entrypoint
                    found_entrypoint = True
                    break
                host = connection_string_to_host(entrypoint)
                result = yield discover_dns(host, protocol.node.test_mode)
                if protocol.connection_string in result:
                    # Found the entrypoint
                    found_entrypoint = True
                    break
            else:
                # When the peer is the server part of the connection we don't have the full connection_string
                # So we can only validate the host from the protocol
                connection_remote = protocol.transport.getPeer()
                connection_host = connection_remote.host
                # Connection host has only the IP
                # So we must consider that the entrypoint could be in name format and we just validate the host
                host = connection_string_to_host(entrypoint)
                if connection_host == host:
                    found_entrypoint = True
                    break
                result = yield discover_dns(host, protocol.node.test_mode)
                if connection_host in [connection_string_to_host(x) for x in result]:
                    # Found the entrypoint
                    found_entrypoint = True
                    break

        if not found_entrypoint:
            # In case the validation fails
            return False

        return True

    def validate_certificate(self, protocol: 'HathorProtocol') -> bool:
        """ Validates if the public key of the connection certificate is the public key of the peer
        """
        # We must validate that the public key used to generate the connection certificate
        # is the same public key from the peer
        connection_cert = protocol.transport.getPeerCertificate()
        cert_pubkey = connection_cert.to_cryptography().public_key()
        cert_pubkey_bytes = cert_pubkey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        assert self.public_key is not None
        peer_pubkey_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        if cert_pubkey_bytes != peer_pubkey_bytes:
            return False

        return True
