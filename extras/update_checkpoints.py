#!/usr/bin/env python
"""
Usage: update_checkpoints.py [-h] [-n NETWORK]

Helper script to update the config checkpoint list.

options:
  -h, --help            show this help message and exit
  -n NETWORK, --network NETWORK
                        The network to update (default: mainnet)

For example:

$ ./extras/update_checkpoints.py
New checkpoints to add for mainnet:

  4_800_000: 00000000000000000716b8d9e96591ba7cb2d02c3d2d1d98d514f41c240fdff7
  4_900_000: 0000000000000000079b1c1ebf48d351a7d31dcc55c5b4cf79ade79089a20f5a
  5_000_000: 000000000000000006c9167db1cc7e93fcf1c3014da6c6221390d03d1640c9b3

  cp(4_800_000, bytes.fromhex('00000000000000000716b8d9e96591ba7cb2d02c3d2d1d98d514f41c240fdff7')),
  cp(4_900_000, bytes.fromhex('0000000000000000079b1c1ebf48d351a7d31dcc55c5b4cf79ade79089a20f5a')),
  cp(5_000_000, bytes.fromhex('000000000000000006c9167db1cc7e93fcf1c3014da6c6221390d03d1640c9b3')),

The output can then be copied and pasted into `hathor/conf/mainnet.yml` and `hathor/conf/mainnet.py`
"""

import requests
import yaml
import argparse

# Built-in network configurations
NETWORKS: dict[str, dict[str, str]] = {
    'mainnet': {
        'config_file': 'hathor/conf/mainnet.yml',
        'node_url': 'https://node1.mainnet.hathor.network/v1a',
    },
    'testnet': {
        'config_file': 'hathor/conf/testnet.yml',
        'node_url': 'https://node1.india.testnet.hathor.network/v1a',
    },
    # Add more networks as needed
}

CHECKPOINT_INTERVAL: int = 100_000


def get_latest_height(node_url: str) -> int:
    """Fetch the latest block height."""
    response = requests.get(f'{node_url}/transaction?type=block&count=1')
    response.raise_for_status()
    return response.json()['transactions'][0]['height']


def get_hash_for_height(node_url: str, height: int) -> str:
    """Fetch the hash for a given block height."""
    response = requests.get(f'{node_url}/block_at_height?height={height}')
    response.raise_for_status()
    return response.json()['block']['tx_id']


def load_checkpoints(config_file: str) -> dict[str, int]:
    """Load the checkpoints from the specified YAML config file."""
    with open(config_file, 'r') as file:
        data = yaml.safe_load(file)
    return data.get('CHECKPOINTS', {})


def print_new_checkpoints(network_name: str) -> None:
    """Print new checkpoints for the specified network."""
    if network_name not in NETWORKS:
        print(f'Error: Unknown network {network_name}. Available networks: {", ".join(NETWORKS.keys())}')
        return

    # Get the network configuration
    network_config = NETWORKS[network_name]
    config_file = network_config['config_file']
    node_url = network_config['node_url']

    # Load existing checkpoints from the YAML file
    current_checkpoints = load_checkpoints(config_file)

    # Get the latest block height
    latest_height = get_latest_height(node_url)

    # Determine missing checkpoints
    new_checkpoints = {}
    for height in range(CHECKPOINT_INTERVAL, latest_height + 1, CHECKPOINT_INTERVAL):
        if height not in current_checkpoints:
            block_hash = get_hash_for_height(node_url, height)
            new_checkpoints[height] = block_hash

    # Print new checkpoints
    if new_checkpoints:
        print(f'New checkpoints to add for {network_name}:\n')
        for height, block_hash in sorted(new_checkpoints.items()):
            print(f'  {height:_}: {block_hash}')
        print()
        for height, block_hash in sorted(new_checkpoints.items()):
            print(f'''  cp({height:_}, bytes.fromhex('{block_hash}')),''')
    else:
        print(f'No new checkpoints needed for {network_name}. All up to date.')


if __name__ == '__main__':
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Helper script to update the config checkpoint list.')
    parser.add_argument('-n', '--network', default='mainnet', help='The network to update (default: mainnet)')
    args = parser.parse_args()

    # Print new checkpoints for the specified network
    print_new_checkpoints(args.network)
