import argparse
import getpass
from hathor.transaction import Transaction
from hathor.wallet.util import generate_signature


def create_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('partial_tx', type=str, help='Tx to be signed in hex')
    parser.add_argument('private_key', type=str, help='Encrypted private key in hex')
    return parser


def execute(args, priv_key_password):
    tx = Transaction.create_from_struct(bytes.fromhex(args.partial_tx))

    signature = generate_signature(tx, bytes.fromhex(args.private_key), password=priv_key_password.encode())
    print('Signature: ', signature.hex())


def main():
    parser = create_parser()
    args = parser.parse_args()
    priv_key_password = getpass.getpass(prompt='Password to decrypt the private key:')
    execute(args, priv_key_password)
