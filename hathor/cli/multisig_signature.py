import getpass
from argparse import ArgumentParser, Namespace


def create_parser() -> ArgumentParser:
    from hathor.cli.util import create_parser
    parser = create_parser()
    parser.add_argument('partial_tx', type=str, help='Tx to be signed in hex')
    parser.add_argument('private_key', type=str, help='Encrypted private key in hex')
    return parser


def execute(args: Namespace, priv_key_password: str) -> None:
    from hathor.transaction import Transaction
    from hathor.wallet.util import generate_signature

    tx = Transaction.create_from_struct(bytes.fromhex(args.partial_tx))
    assert isinstance(tx, Transaction)

    signature = generate_signature(tx, bytes.fromhex(args.private_key), password=priv_key_password.encode())
    print('Signature: ', signature.hex())


def main():
    parser = create_parser()
    args = parser.parse_args()
    priv_key_password = getpass.getpass(prompt='Password to decrypt the private key:')
    execute(args, priv_key_password)
