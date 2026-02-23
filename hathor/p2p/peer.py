# Copyright 2021 Hathor Labs
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
"""
This module exposes three peer classes that share similar behavior but must not be mixed.

This is the class structure:

    PeerInfo has entrypoints and reconnect info
    UnverifiedPeer has a PeerId and PeerInfo
    PublicPeer has an UnverifiedPeer and a public-key
    PrivatePeer has a PublicPeer and a private-key

This way the shared behavior is implemented and propagated through the private classes, and the public classes don't
share the same inheritance tree and for example a `peer: PublicPeer` will have `isinstance(peer, UnverifiedPeer) ==
False`, so they can't be mixed.

This makes it harder for external functions to support "subtypes" by accepting a base class, but this is intentional.
If a function can work for any type of peer, it should be defined as `def foo(peer: UnverifiedPeer)` and callers will
have to call `private_peer.to_unverified_peer()` because `PrivatePeer` is not a subclass of `UnverifiedPeer`.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from functools import cached_property
from math import inf
from typing import TYPE_CHECKING, Any, cast

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from OpenSSL.crypto import X509, PKey
from structlog import get_logger
from twisted.internet.interfaces import ISSLTransport
from twisted.internet.ssl import Certificate, CertificateOptions, TLSVersion, trustRootFromCertificates
from typing_extensions import Self

from hathor.conf.get_settings import get_global_settings
from hathor.conf.settings import HathorSettings
from hathor.daa import DifficultyAdjustmentAlgorithm
from hathor.p2p.peer_endpoint import PeerAddress, PeerEndpoint
from hathor.p2p.peer_id import PeerId
from hathor.p2p.utils import discover_dns, generate_certificate
from hathor.util import not_none

if TYPE_CHECKING:
    from hathor.p2p.protocol import HathorProtocol  # noqa: F401

logger = get_logger()


class InvalidPeerIdException(Exception):
    pass


class PeerFlags(str, Enum):
    RETRIES_EXCEEDED = 'retries_exceeded'


def _parse_pubkey(pubkey_string: str) -> rsa.RSAPublicKey:
    """ Helper function to parse a public key from string."""
    public_key_der = base64.b64decode(pubkey_string)
    public_key = serialization.load_der_public_key(data=public_key_der, backend=default_backend())
    assert public_key is not None
    return public_key


def _parse_privkey(privkey_string: str) -> rsa.RSAPrivateKeyWithSerialization:
    """ Helper function to parse a private key from string."""
    private_key_der = base64.b64decode(privkey_string)
    private_key = serialization.load_der_private_key(data=private_key_der, password=None, backend=default_backend())
    assert private_key is not None
    return private_key


def _calculate_peer_id(public_key: rsa.RSAPublicKey) -> PeerId:
    """ Helper function to calculate a peer id from a public key."""
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    h1 = hashlib.sha256(public_der)
    h2 = hashlib.sha256(h1.digest())
    return PeerId(h2.digest())


@dataclass(kw_only=True, slots=True)
class PeerInfo:
    """ Stores entrypoint and connection attempts information.
    """

    entrypoints: set[PeerAddress] = field(default_factory=set)
    retry_timestamp: int = 0  # should only try connecting to this peer after this timestamp
    retry_interval: int = 5  # how long to wait for next connection retry. It will double for each failure
    retry_attempts: int = 0  # how many retries were made
    last_seen: float = inf  # last time this peer was seen
    flags: set[str] = field(default_factory=set)
    _settings: HathorSettings = field(default_factory=get_global_settings, repr=False)

    def get_ipv4_only_entrypoints(self) -> list[PeerAddress]:
        return list(filter(lambda e: not e.is_ipv6(), self.entrypoints))

    def get_ipv6_only_entrypoints(self) -> list[PeerAddress]:
        return list(filter(lambda e: e.is_ipv6(), self.entrypoints))

    def ipv4_entrypoints_as_str(self) -> list[str]:
        return sorted(map(str, self.get_ipv4_only_entrypoints()))

    def ipv6_entrypoints_as_str(self) -> list[str]:
        return sorted(map(str, self.get_ipv6_only_entrypoints()))

    def entrypoints_as_str(self) -> list[str]:
        """Return a list of entrypoints serialized as str"""
        return sorted(map(str, self.entrypoints))

    def _merge(self, other: PeerInfo) -> None:
        """Actual merge execution, must only be made after verifications."""
        self.entrypoints.update(other.entrypoints)

    async def validate_entrypoint(self, protocol: HathorProtocol) -> bool:
        """ Validates if connection entrypoint is one of the peer entrypoints
        """
        # If has no entrypoints must be behind a NAT, so we add the flag to the connection
        if len(self.entrypoints) == 0:
            protocol.warning_flags.add(protocol.WarningFlags.NO_ENTRYPOINTS)
            # If there are no entrypoints, we don't need to validate it
            return True

        # Entrypoint validation with connection string and connection host
        # Entrypoints have the format tcp://IP|name:port
        for entrypoint in self.entrypoints:
            # Connection string has the format tcp://IP:port
            # So we must consider that the entrypoint could be in name format
            if protocol.addr == entrypoint:
                return True
            # TODO: don't use `daa.TEST_MODE` for this
            test_mode = not_none(DifficultyAdjustmentAlgorithm.singleton).TEST_MODE
            result = await discover_dns(entrypoint.host, test_mode)
            for endpoint in result:
                if protocol.addr == endpoint.addr:
                    return True

        return False

    def increment_retry_attempt(self, now: int) -> None:
        """ Updates timestamp for next retry.

        :param now: current timestamp
        """
        self.retry_timestamp = now + self.retry_interval
        self.retry_attempts += 1
        self.retry_interval = self.retry_interval * self._settings.PEER_CONNECTION_RETRY_INTERVAL_MULTIPLIER
        if self.retry_interval > self._settings.PEER_CONNECTION_RETRY_MAX_RETRY_INTERVAL:
            self.retry_interval = self._settings.PEER_CONNECTION_RETRY_MAX_RETRY_INTERVAL

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
        if now < self.retry_timestamp:
            return False
        return True


@dataclass(slots=True)
class UnverifiedPeer:
    """ Represents a peer with an unverified id and entrypoint list, which we can try to connect to.
    """

    id: PeerId
    info: PeerInfo = field(default_factory=PeerInfo)

    def to_json(self, only_ipv4_entrypoints: bool = True) -> dict[str, Any]:
        """ Return a JSON serialization of the object.

        This format is compatible with libp2p.
        """
        if only_ipv4_entrypoints:
            entrypoints_as_str = self.info.ipv4_entrypoints_as_str()
        else:
            entrypoints_as_str = self.info.entrypoints_as_str()

        return {
            'id': str(self.id),
            'entrypoints': entrypoints_as_str,
        }

    @classmethod
    def create_from_json(cls, data: dict[str, Any]) -> Self:
        """ Create a new UnverifiedPeer from JSON data.

        It is to create an UnverifiedPeer from a peer connection.
        """
        peer_id = PeerId(data['id'])
        endpoints = set()

        for endpoint_str in data.get('entrypoints', []):
            # We have to parse using PeerEndpoint to be able to support older peers that still
            # send the id in entrypoints, but we validate that they're sending the correct id.
            endpoint = PeerEndpoint.parse(endpoint_str)
            if endpoint.peer_id is not None and endpoint.peer_id != peer_id:
                raise ValueError(f'conflicting peer_id: {endpoint.peer_id} != {peer_id}')
            endpoints.add(endpoint.addr)

        obj = cls(
            id=peer_id,
            info=PeerInfo(entrypoints=endpoints),
        )
        obj.validate()
        return obj

    def merge(self, other: UnverifiedPeer) -> None:
        """ Merge two UnverifiedPeer objects, checking that they have the same
        id, public_key, and private_key. The entrypoints are merged without
        duplicating their entries.
        """
        assert self.id == other.id
        self.info._merge(other.info)
        self.validate()

    def validate(self) -> None:
        """Check if there are too many entrypoints."""
        if len(self.info.entrypoints) > self.info._settings.PEER_MAX_ENTRYPOINTS:
            raise InvalidPeerIdException('too many entrypoints')


@dataclass(slots=True)
class PublicPeer:
    """ Represents a peer that can verify signatures, and thus communicate to.
    """

    _peer: UnverifiedPeer
    public_key: rsa.RSAPublicKey

    @property
    def id(self) -> PeerId:
        return self._peer.id

    @property
    def info(self) -> PeerInfo:
        return self._peer.info

    def to_unverified_peer(self) -> UnverifiedPeer:
        """Convert to a simple UnverifiedPeer."""
        return self._peer

    def to_json(self) -> dict[str, Any]:
        """ Return a JSON serialization of the object.

        This format is compatible with libp2p.
        """
        public_der = self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return {
            **self._peer.to_json(),
            'pubKey': base64.b64encode(public_der).decode('utf-8'),
        }

    @classmethod
    def create_from_json(cls, data: dict[str, Any]) -> Self:
        """ Create a new PublicPeer from JSON data.

        It is used to create a PublicPeer from that same peer.
        """
        public_key = _parse_pubkey(data['pubKey'])
        peer = UnverifiedPeer.create_from_json(data)
        obj = cls(
            _peer=peer,
            public_key=public_key,
        )
        obj.validate()
        return obj

    def calculate_id(self) -> PeerId:
        """ Calculate and return the id based on the public key.
        """
        return _calculate_peer_id(self.public_key)

    def get_public_key(self) -> str:
        """ Return the public key in DER encoding as an `str`.
        """
        public_der = self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return base64.b64encode(public_der).decode('utf-8')

    def validate_certificate(self, protocol: HathorProtocol) -> bool:
        """ Validates if the public key of the connection certificate is the public key of the peer
        """
        assert protocol.transport is not None
        # from hathor.simulator.fake_connection import HathorStringTransport
        # assert isinstance(protocol.transport, (ISSLTransport, HathorStringTransport))
        # FIXME: we can't easily use the above strategy because ISSLTransport is a zope.interface and thus won't have
        #        an "isinstance" relation, and HathorStringTransport does not implement the zope.interface, but does
        #        implement the needed "sub-interface" for this method, a typing.cast is being used to fool mypy, but we
        #        should come up with a proper solution
        transport = cast(ISSLTransport, protocol.transport)

        # We must validate that the public key used to generate the connection certificate
        # is the same public key from the peer
        connection_cert = cast(X509, transport.getPeerCertificate())
        cert_pubkey = connection_cert.to_cryptography().public_key()
        cert_pubkey_bytes = cert_pubkey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        peer_pubkey_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        if cert_pubkey_bytes != peer_pubkey_bytes:
            return False

        return True

    def verify_signature(self, signature: bytes, data: bytes) -> bool:
        """ Verify a signature of a data. Both must be of type `bytes`.
        """
        try:
            self.public_key.verify(
                signature,
                data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
        except InvalidSignature:
            return False
        else:
            return True

    def validate(self) -> None:
        """Calculate the PeerId based on the public key and raise an exception if it does not match."""
        if self.id != self.calculate_id():
            raise InvalidPeerIdException('id does not match public key')

    def merge(self, other: PublicPeer) -> None:
        """ Merge two PublicPeer objects, checking that they have the same
        id, public_key, and private_key. The entrypoints are merged without
        duplicating their entries.
        """
        assert self.id == other.id
        assert self.get_public_key() == other.get_public_key()
        self._peer.merge(other._peer)
        self.validate()


# XXX: no slots because we have cached properties
@dataclass
class PrivatePeer:
    """ Represents a peer that can be used to sign messages, and thus communicate from.
    """

    _public_peer: PublicPeer
    private_key: rsa.RSAPrivateKeyWithSerialization
    _source_file: str | None = None

    @property
    def id(self) -> PeerId:
        return self._public_peer._peer.id

    @property
    def info(self) -> PeerInfo:
        return self._public_peer._peer.info

    @property
    def public_key(self) -> rsa.RSAPublicKey:
        return self._public_peer.public_key

    def to_unverified_peer(self) -> UnverifiedPeer:
        """Convert to a simple UnverifiedPeer."""
        return self._public_peer._peer

    def to_public_peer(self) -> PublicPeer:
        """Convert to a simple PublicPeer."""
        return self._public_peer

    def to_json(self) -> dict[str, Any]:
        """ Return a JSON serialization of the object without the private key.

        This format is compatible with libp2p.
        """
        return self._public_peer.to_json()

    def to_json_private(self) -> dict[str, Any]:
        """ Return a JSON serialization of the object with the private key.

        This format is compatible with libp2p.
        """
        private_der = self.private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            # TODO encryption_algorithm=serialization.BestAvailableEncryption(b'mypassword')
            encryption_algorithm=serialization.NoEncryption(),
        )
        return {
            **self._public_peer.to_json(),
            'privKey': base64.b64encode(private_der).decode('utf-8'),
        }

    def get_public_key(self) -> str:
        """ Return the public key in DER encoding as an `str`.
        """
        return self._public_peer.get_public_key()

    @classmethod
    def create_from_json(cls, data: dict[str, Any]) -> Self:
        private_key = _parse_privkey(data['privKey'])
        public_peer = PublicPeer.create_from_json(data)
        obj = cls(
            _public_peer=public_peer,
            private_key=private_key
        )
        obj.validate()
        return obj

    def validate(self) -> None:
        self._public_peer.validate()
        public_der1 = self._public_peer.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        public_der2 = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if public_der1 != public_der2:
            raise InvalidPeerIdException('private/public pair does not match')

    @classmethod
    def auto_generated(cls, key_size: int = 2048) -> Self:
        """ Generate a random pair of private key and public key.
        It also calculates the id of this peer, based on its public key.
        """
        # https://security.stackexchange.com/questions/5096/rsa-vs-dsa-for-ssh-authentication-keys
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend(),
        )
        public_key = private_key.public_key()
        return cls(
            _public_peer=PublicPeer(
                _peer=UnverifiedPeer(id=_calculate_peer_id(public_key)),
                public_key=public_key,
            ),
            private_key=private_key,
        )

    def sign(self, data: bytes) -> bytes:
        """ Sign any data (of type `bytes`).
        """
        return self.private_key.sign(
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )

    @cached_property
    def certificate(self) -> x509.Certificate:
        """ Return certificate generated and signed with peer private key.

        The result is cached so subsequent calls are really cheap.
        """
        _settings = self._public_peer._peer.info._settings
        return generate_certificate(
            self.private_key,
            _settings.CA_FILEPATH,
            _settings.CA_KEY_FILEPATH,
        )

    @cached_property
    def certificate_options(self) -> CertificateOptions:
        """ Return certificate options with certificate generated and signed with peer private key.

        The result is cached so subsequent calls are really cheap.
        """
        _settings = self._public_peer._peer.info._settings
        openssl_certificate = X509.from_cryptography(self.certificate)
        openssl_pkey = PKey.from_cryptography_key(self.private_key)

        with open(_settings.CA_FILEPATH, 'rb') as f:
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

    @classmethod
    def create_from_json_path(cls, path: str) -> Self:
        """Create a new PrivatePeer from a JSON file."""
        data = json.load(open(path, 'r'))
        peer = cls.create_from_json(data)
        peer._source_file = path
        return peer

    def reload_entrypoints_from_source_file(self) -> None:
        """Update this PrivatePeer's entrypoints from the json file."""
        if not self._source_file:
            raise ValueError('Trying to reload entrypoints but no peer config file was provided.')

        new_peer = PrivatePeer.create_from_json_path(self._source_file)

        if new_peer.id != self.id:
            logger.error(
                'Ignoring peer id file update because the peer_id does not match.',
                current_peer_id=self.id,
                new_peer_id=new_peer.id,
            )
            return

        self._public_peer._peer.info.entrypoints = new_peer._public_peer._peer.info.entrypoints

    def save_to_file(self, path: str) -> None:
        """ Save the object to a JSON file.
        """
        import json
        data = self.to_json_private()
        fp = open(path, 'w')
        json.dump(data, fp, indent=4)
        fp.close()
