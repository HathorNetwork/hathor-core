#!/usr/bin/python3

import atheris

with atheris.instrument_imports():
    import sys
    from hathor.transaction.exceptions import InvalidOutputValue
    from hathor.transaction import Block, MergeMinedBlock, Transaction
    from hathor.transaction.token_creation_tx import TokenCreationTransaction

def TestOneInput(data):
    if len(data) < 5:
        return

    try:
        Block.create_from_struct(data)
        MergeMinedBlock.create_from_struct(data)
        Transaction.create_from_struct(data)
        TokenCreationTransaction.create_from_struct(data)
    except (ValueError, InvalidOutputValue):
        pass

def main():
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
