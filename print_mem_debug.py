#!/bin/env python
import argparse

from guppy import hpy


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('file')
    args = parser.parse_args()
    print(hpy().load(args.file))


if __name__ == '__main__':
    main()
