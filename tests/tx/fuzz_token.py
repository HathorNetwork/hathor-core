#!/usr/bin/python3

import atheris

with atheris.instrument_imports():
    import sys
    from hathor.transaction.token_creation_tx import TokenCreationTransaction

def TestOneInput(data):
    if len(data) < 10:
        return

    try:
        TokenCreationTransaction.deserialize_token_info(data)
    except ValueError:
        pass

def main():
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
