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

import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec


def main():
    from hathor_cli.util import create_parser
    from hathor.crypto.util import get_hash160, get_private_key_bytes, get_public_key_bytes_compressed

    parser = create_parser()

    parser.add_argument('filepath', help='Create a new private key in the given file')
    args = parser.parse_args()

    new_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
    private_key_bytes = get_private_key_bytes(new_key)
    with open(args.filepath, 'w') as key_file:
        key_file.write(base64.b64encode(private_key_bytes).decode('utf-8'))
        print('key created!')
    public_key_bytes = get_public_key_bytes_compressed(new_key.public_key())
    print('base64 pubkey hash:', base64.b64encode(get_hash160(public_key_bytes)).decode('utf-8'))
