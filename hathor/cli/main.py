"""
Copyright 2019 Hathor Labs

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import os
import sys
from collections import defaultdict
from types import ModuleType
from typing import Dict, List, Optional

from structlog import get_logger

logger = get_logger()


class CliManager:
    def __init__(self) -> None:
        self.basename: str = os.path.basename(sys.argv[0])
        self.command_list: Dict[str, ModuleType] = {}
        self.cmd_description: Dict[str, str] = {}
        self.groups: Dict[str, List[str]] = defaultdict(list)
        self.longest_cmd: int = 0

        from . import (
            generate_valid_words,
            merged_mining,
            mining,
            multisig_address,
            multisig_signature,
            multisig_spend,
            nginx_config,
            openapi_json,
            oracle_create_key,
            oracle_encode_data,
            oracle_get_pubkey,
            peer_id,
            run_node,
            shell,
            stratum_mining,
            twin_tx,
            tx_generator,
            wallet,
        )

        self.add_cmd('mining', 'run_miner', mining, 'Run a mining process (running node required)')
        self.add_cmd('mining', 'run_merged_mining', merged_mining,
                     'Run a merged mining coordinator (hathor and bitcoin nodes required)')
        self.add_cmd('mining', 'run_stratum_miner', stratum_mining, 'Run a mining process (running node required)')
        self.add_cmd('hathor', 'run_node', run_node, 'Run a node')
        self.add_cmd('hathor', 'gen_peer_id', peer_id, 'Generate a new random peer-id')
        self.add_cmd('docs', 'generate_openapi_json', openapi_json, 'Generate OpenAPI json for API docs')
        self.add_cmd('multisig', 'gen_multisig_address', multisig_address, 'Generate a new multisig address')
        self.add_cmd('multisig', 'spend_multisig_output', multisig_spend, 'Generate tx that spends a multisig output')
        self.add_cmd('multisig', 'tx_signature', multisig_signature, 'Generate a signature of a multisig tx')
        self.add_cmd('tests', 'gen_rand_tx', tx_generator, 'Generate random transactions (running node required)')
        self.add_cmd('tests', 'gen_twin_tx', twin_tx, 'Generate a twin transaction from a transaction hash')
        self.add_cmd('wallet', 'gen_kp_wallet', wallet, 'Generate a new KeyPair wallet')
        self.add_cmd('wallet', 'gen_hd_words', generate_valid_words, 'Generate random words for HD wallet')
        self.add_cmd('oracle', 'oracle-create-key', oracle_create_key, 'Create an oracle private/public key')
        self.add_cmd('oracle', 'oracle-get-pubkey', oracle_get_pubkey,
                     'Read an oracle private key and output public key hash')
        self.add_cmd('oracle', 'oracle-encode-data', oracle_encode_data, 'Encode data and sign it with a private key')
        self.add_cmd('dev', 'shell', shell, 'Run a Python shell')
        self.add_cmd('dev', 'generate_nginx_config', nginx_config, 'Generate nginx config from OpenAPI json')

    def add_cmd(self, group: str, cmd: str, module: ModuleType, short_description: Optional[str] = None) -> None:
        self.command_list[cmd] = module
        self.groups[group].append(cmd)
        if short_description:
            self.cmd_description[cmd] = short_description
        self.longest_cmd = max(self.longest_cmd, len(cmd))

    def help(self) -> None:
        print()
        print('Available subcommands:')
        print()

        groups = list(self.groups.keys())
        groups.sort()

        from colorama import Fore, Style
        for group in groups:
            print(Fore.RED + Style.BRIGHT + '[{}]'.format(group) + Style.RESET_ALL)
            for cmd in self.groups[group]:
                filling = ' ' * (self.longest_cmd - len(cmd))
                description = self.cmd_description.get(cmd, '')
                print('    {}{}   {}'.format(cmd, filling, description))
            print()

    def execute_from_command_line(self):
        from hathor.cli.util import setup_logging

        if len(sys.argv) < 2:
            self.help()
            return 0

        cmd = sys.argv.pop(1)
        if cmd == 'help':
            self.help()
            return 0

        if cmd not in self.command_list:
            print('Unknown command: "{}"'.format(cmd))
            print('Type "{} help" for usage.'.format(self.basename))
            return -1

        sys.argv[0] = '{} {}'.format(sys.argv[0], cmd)
        module = self.command_list[cmd]

        debug = '--debug' in sys.argv
        if debug:
            sys.argv.remove('--debug')
        if '--help' in sys.argv:
            capture_stdout = False
        else:
            capture_stdout = getattr(module, 'LOGGING_CAPTURE_STDOUT', False)

        # Enable pudb to stop on an unhandled exception.
        pudb = '--pudb' in sys.argv
        if pudb:
            sys.argv.remove('--pudb')
            import pudb
            pudb.set_trace(paused=False)
            capture_stdout = False

        setup_logging(debug, capture_stdout)
        module.main()


def main():
    try:
        sys.exit(CliManager().execute_from_command_line())
    except KeyboardInterrupt:
        logger.warn('Aborting and exiting...')
        sys.exit(1)
    except Exception:
        logger.exception('Uncaught exception:')
        sys.exit(2)


if __name__ == '__main__':
    main()
