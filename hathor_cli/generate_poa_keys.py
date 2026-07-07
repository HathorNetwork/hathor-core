# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

import json
import os
import sys

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKeyWithSerialization


def main():
    from hathor_cli.util import create_parser
    from hathor.crypto.util import (
        get_address_b58_from_public_key,
        get_private_key_bytes,
        get_public_key_bytes_compressed,
    )
    parser = create_parser()
    parser.add_argument('--config-yaml', type=str, help='Configuration yaml filepath')
    args = parser.parse_args(sys.argv[1:])
    if not args.config_yaml:
        raise Exception('`--config-yaml` is required')
    # We have to set the config file because the `get_address_b58_from_public_key()` call below accesses it indirectly
    # to use the version bytes.
    os.environ['HATHOR_CONFIG_YAML'] = args.config_yaml

    private_key = ec.generate_private_key(ec.SECP256K1())
    public_key = private_key.public_key()
    assert isinstance(private_key, EllipticCurvePrivateKeyWithSerialization)

    data = dict(
        private_key_hex=get_private_key_bytes(private_key=private_key).hex(),
        public_key_hex=get_public_key_bytes_compressed(public_key=public_key).hex(),
        address=get_address_b58_from_public_key(public_key=public_key),
    )

    print(json.dumps(data, indent=4))
