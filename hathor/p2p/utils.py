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

import re
from datetime import UTC, datetime, timedelta
from typing import Any, Optional

import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import Certificate
from cryptography.x509.oid import NameOID
from structlog import get_logger
from twisted.internet.interfaces import IAddress

from hathor.conf.get_settings import get_global_settings
from hathor.conf.settings import HathorSettings
from hathor.indexes.height_index import HeightInfo
from hathor.p2p.peer_discovery import DNSPeerDiscovery
from hathor.p2p.peer_endpoint import PeerEndpoint
from hathor.transaction.genesis import get_representation_for_all_genesis

logger = get_logger()


def discover_hostname(timeout: float | None = None) -> Optional[str]:
    """ Try to discover your hostname. It is a synchronous operation and
    should not be called from twisted main loop.
    """
    return discover_ip_ipify(timeout)


def discover_ip_ipify(timeout: float | None = None) -> Optional[str]:
    """ Try to discover your IP address using ipify's api.
    It is a synchronous operation and should not be called from twisted main loop.
    """
    response = requests.get('https://api.ipify.org', timeout=timeout)
    if response.ok:
        # It may be either an ipv4 or ipv6 in string format.
        ip = response.text
        return ip
    return None


def get_genesis_short_hash() -> str:
    """ Return the first 7 chars of the GENESIS_HASH used for validation that the genesis are the same
    """
    settings = get_global_settings()
    return get_representation_for_all_genesis(settings).hex()[:7]


def get_settings_hello_dict(settings: HathorSettings) -> dict[str, Any]:
    """ Return a dict of settings values that must be validated in the hello state
    """
    settings_dict = {}
    for key in settings.P2P_SETTINGS_HASH_FIELDS:
        value = getattr(settings, key)
        # We are going to json.dumps this dict, so we can't have bytes here
        if type(value) is bytes:
            value = value.hex()
        settings_dict[key] = value

    if consensus_hash := settings.CONSENSUS_ALGORITHM.get_peer_hello_hash():
        settings_dict['CONSENSUS_ALGORITHM'] = consensus_hash

    return settings_dict


async def discover_dns(host: str, test_mode: int = 0) -> list[PeerEndpoint]:
    """ Start a DNS peer discovery object and execute a search for the host

        Returns the DNS string from the requested host
        E.g., localhost -> tcp://127.0.0.1:40403
    """
    discovery = DNSPeerDiscovery([], test_mode=test_mode)
    result = await discovery.dns_seed_lookup(host)
    return list(result)


def generate_certificate(private_key: RSAPrivateKey, ca_file: str, ca_pkey_file: str) -> Certificate:
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

    builder = builder.not_valid_before(datetime.now(UTC) - timedelta(hours=1))
    builder = builder.not_valid_after(datetime.now(UTC) + timedelta(hours=24*365*100))
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


def parse_file(text: str, *, header: Optional[str] = None) -> list[str]:
    """Parses a list of strings."""
    if header is None:
        header = 'hathor-whitelist'
    lines = text.splitlines()
    _header = lines.pop(0)
    if _header != header:
        raise ValueError('invalid header')
    stripped_lines = (line.strip() for line in lines)
    nonblank_lines = filter(lambda line: line and not line.startswith('#'), stripped_lines)
    return list(nonblank_lines)


def format_address(addr: IAddress) -> str:
    """ Return a string with '{host}:{port}' when possible, otherwise use the addr's __str__
    """
    host: Optional[str] = getattr(addr, 'host', None)
    port: Optional[str] = getattr(addr, 'port', None)
    if host is not None and port is not None:
        return f'{host}:{port}'
    else:
        return str(addr)


def to_height_info(raw: tuple[int, str]) -> HeightInfo:
    """ Instantiate HeightInfo from a literal tuple.
    """
    if not (isinstance(raw, list) and len(raw) == 2):
        raise ValueError(f"height_info_raw must be a tuple with length 2. We got {raw}.")

    height, id = raw

    if not isinstance(id, str):
        raise ValueError(f"id (hash) must be a string. We got {id}.")
    hash_pattern = r'[a-fA-F\d]{64}'
    if not re.match(hash_pattern, id):
        raise ValueError(f"id (hash) must be valid. We got {id}.")
    if not isinstance(height, int):
        raise ValueError(f"height must be an integer. We got {height}.")
    if height < 0:
        raise ValueError(f"height must be greater than or equal to 0. We got {height}.")

    return HeightInfo(height, bytes.fromhex(id))


def to_serializable_best_blockchain(best_blockchain: list[HeightInfo]) -> list[tuple[int, str]]:
    """ Converts the list of HeightInfo to a tuple list that can be serializable to json afterwards.
    """
    return [(hi.height, hi.id.hex()) for hi in best_blockchain]
