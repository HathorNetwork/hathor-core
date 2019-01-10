import argparse
from argparse import ArgumentParser, Namespace


def create_parser() -> ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument('partial_tx', type=str, help='Tx to spend multisig fund')
    parser.add_argument(
        'signatures', type=str,
        help='Signatures in hex of the private keys in the same order as the public keys (separated by a comma)')
    parser.add_argument('redeem_script', type=str, help='Redeem script in hex')
    return parser


def execute(args: Namespace) -> None:
    from hathor.transaction import Transaction
    from hathor.transaction.scripts import MultiSig

    tx = Transaction.create_from_struct(bytes.fromhex(args.partial_tx))

    signatures = [bytes.fromhex(signature) for signature in args.signatures.split(',')]
    input_data = MultiSig.create_input_data(bytes.fromhex(args.redeem_script), signatures)
    tx.inputs[0].data = input_data

    tx.resolve()
    print('Transaction after POW: ', tx.get_struct().hex())


def main():
    parser = create_parser()
    args = parser.parse_args()
    execute(args)
