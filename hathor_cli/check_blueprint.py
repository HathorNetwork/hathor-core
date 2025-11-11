# Copyright 2024 Hathor Labs
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

import os
import sys
from argparse import FileType
from io import TextIOWrapper


def main() -> None:
    from hathor_cli.util import create_parser
    from hathor.conf import NANO_TESTNET_SETTINGS_FILEPATH
    from hathor.conf.get_settings import get_global_settings
    from hathor.nanocontracts import OnChainBlueprint
    from hathor.nanocontracts.on_chain_blueprint import Code
    from hathor.verification.on_chain_blueprint_verifier import OnChainBlueprintVerifier

    os.environ['HATHOR_CONFIG_YAML'] = NANO_TESTNET_SETTINGS_FILEPATH

    parser = create_parser()
    parser.add_argument(
        '--file',
        type=FileType('r', encoding='UTF-8'),
        help='The blueprint file',
        required=True,
    )
    args = parser.parse_args(sys.argv[1:])
    assert isinstance(args.file, TextIOWrapper)

    settings = get_global_settings()
    code = Code.from_python_code(args.file.read(), settings)
    verifier = OnChainBlueprintVerifier(settings=settings)
    ocb = OnChainBlueprint(hash=b'', code=code)

    verifier.verify_code(ocb)
    print('Blueprint is valid!')
