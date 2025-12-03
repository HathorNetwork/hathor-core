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
