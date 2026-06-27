# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

import os
import sys
from argparse import FileType
from io import TextIOWrapper


def main() -> None:
    from hathor.conf.get_settings import get_global_settings
    from hathor.nanocontracts import OnChainBlueprint
    from hathor.nanocontracts.on_chain_blueprint import Code
    from hathor.verification.on_chain_blueprint_verifier import OnChainBlueprintVerifier
    from hathor_cli.util import create_parser
    from hathorlib.conf import NANO_TESTNET_SETTINGS_FILEPATH

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
