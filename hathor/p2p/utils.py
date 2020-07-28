import datetime
from typing import TYPE_CHECKING, Any, Generator, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509.oid import NameOID
from twisted.internet.defer import inlineCallbacks

from hathor.conf import HathorSettings
from hathor.p2p.peer_discovery import DNSPeerDiscovery
from hathor.transaction.genesis import GENESIS_HASH
from hathor.util import JsonDict

if TYPE_CHECKING:
    from cryptography.hazmat.backends.openssl.rsa import _RSAPrivateKey
    from cryptography.x509 import Certificate

settings = HathorSettings()


def discover_hostname() -> Optional[str]:
    """ Try to discover your hostname. It is a synchonous operation and
    should not be called from twisted main loop.
    """
    return discover_ip_ipify()


def discover_ip_ipify() -> Optional[str]:
    """ Try to discover your IP address using ipify's api.
    It is a synchonous operation and should not be called from twisted main loop.
    """
    response = requests.get('https://api.ipify.org')
    if response.ok:
        # It may be either an ipv4 or ipv6 in string format.
        ip = response.text
        return ip
    return None


def description_to_connection_string(description: str) -> Tuple[str, Optional[str]]:
    """ The description returned from DNS query may contain a peer-id parameter
        This method splits this description into the connection URL and the peer-id (in case it exists)
        Expected description is something like: tcp://127.0.0.1:40403/?id=123
        The expected returned tuple in this case would be ('tcp://127.0.0.1:40403', '123')
    """
    result = urlparse(description)

    url = "{}://{}".format(result.scheme, result.netloc)
    peer_id = None

    if result.query:
        query_result = parse_qs(result.query)
        if 'id' in query_result:
            peer_id = query_result['id'][0]

    return url, peer_id


def get_genesis_short_hash() -> str:
    """ Return the first 7 chars of the GENESIS_HASH used for validation that the genesis are the same
    """
    return GENESIS_HASH.hex()[:7]


def get_settings_hello_dict() -> JsonDict:
    """ Return a dict of settings values that must be validated in the hello state
    """
    settings_dict = {}
    for key in settings.P2P_SETTINGS_HASH_FIELDS:
        value = getattr(settings, key)
        # We are going to json_dumps this dict, so we can't have bytes here
        if type(value) == bytes:
            value = value.hex()
        settings_dict[key] = value
    return settings_dict


def connection_string_to_host(connection_string: str) -> str:
    """ From a connection string I return the host
        tcp://127.0.0.1:40403 -> 127.0.0.1
    """
    return urlparse(connection_string).netloc.split(':')[0]


@inlineCallbacks
def discover_dns(host: str, test_mode: int = 0) -> Generator[Any, Any, List[str]]:
    """ Start a DNS peer discovery object and execute a search for the host

        Returns the DNS string from the requested host
        E.g., localhost -> tcp://127.0.0.1:40403
    """
    discovery = DNSPeerDiscovery([], test_mode=test_mode)
    result = yield discovery.dns_seed_lookup(host)
    return result


def generate_certificate(private_key: '_RSAPrivateKey', ca_file: str, ca_pkey_file: str) -> 'Certificate':
    """ Generate a certificate signed by the ca file passed as parameters
        This certificate is used to start the TLS connection between peers and contains the peer public key
    """
    _BACKEND = default_backend()

    with open(ca_file, 'rb') as f:
        ca = x509.load_pem_x509_certificate(data=f.read(), backend=_BACKEND)

    with open(ca_pkey_file, 'rb') as f:
        ca_pkey = load_pem_private_key(f.read(), password=None, backend=_BACKEND)

    public_key = private_key.public_key()
    builder = x509.CertificateBuilder()

    builder = builder.issuer_name(ca.issuer)

    subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, 'Hathor full node')
    ])
    builder = builder.subject_name(subject)

    builder = builder.not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(hours=1))
    builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(hours=24*365*100))
    builder = builder.serial_number(x509.random_serial_number())

    builder = builder.public_key(public_key)

    builder = builder.add_extension(
            x509.BasicConstraints(
                    ca=False, path_length=None), critical=True)

    certificate = builder.sign(
        private_key=ca_pkey,
        algorithm=hashes.SHA256(),
        backend=_BACKEND
    )

    return certificate
