
import sys
import os
from collections import defaultdict


class CliManager:
    def __init__(self):
        self.basename = os.path.basename(sys.argv[0])
        self.command_list = {}  # Dict[str, module]
        self.cmd_description = {}  # Dict[str, str]
        self.groups = defaultdict(list)  # Dict[str, List[str]]
        self.longest_cmd = 0

        from . import mining
        from . import peer_id
        from . import run_node
        from . import tx_generator
        from . import wallet
        from . import generate_valid_words
        from . import grafana_dashboard
        from . import twin_tx

        self.add_cmd('mining', 'run_miner', mining, 'Run a mining process (running node required)')
        self.add_cmd('hathor', 'run_node', run_node, 'Run a node')
        self.add_cmd('hathor', 'gen_peer_id', peer_id, 'Generate a new random peer-id')
        self.add_cmd('tests', 'gen_rand_tx', tx_generator, 'Generate random transactions (running node required)')
        self.add_cmd('tests', 'gen_twin_tx', twin_tx, 'Generate a twin transaction from a transaction hash')
        self.add_cmd('wallet', 'gen_kp_wallet', wallet, 'Generate a new KeyPair wallet')
        self.add_cmd('wallet', 'gen_hd_words', generate_valid_words, 'Generate random words for HD wallet')
        self.add_cmd('grafana', 'grafana_dashboard', grafana_dashboard,
                     'Generate a Grafana Dashboard with all nodes and metrics')

    def add_cmd(self, group, cmd, module, short_description=None):
        self.command_list[cmd] = module
        self.groups[group].append(cmd)
        if short_description:
            self.cmd_description[cmd] = short_description
        self.longest_cmd = max(self.longest_cmd, len(cmd))

    def help(self):
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
        module.main()


def main():
    sys.exit(CliManager().execute_from_command_line())


if __name__ == '__main__':
    main()
