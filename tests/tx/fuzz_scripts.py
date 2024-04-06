#!/usr/bin/python3

import atheris

with atheris.instrument_imports():
    import sys
    from hathor.transaction.scripts import HathorScript, parse_address_script

def TestOneInput(data):

    try:
        s = HathorScript()
        s.pushData(bytes(data))
    except ValueError:
        pass

    parse_address_script(data)

def main():
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
