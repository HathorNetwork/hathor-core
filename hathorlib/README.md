hathorlib
=========

Hathor Network base library.

## Configuration

To install dependencies, including optionals, run:

    poetry install -E client

## Running the tests

To run the tests using poetry virtualenv:

    poetry run make tests

If are managing virtualenvs without poetry, make sure it's activated and run:

    make tests

## Running linters

To run linters:

    poetry run make check

Or without poetry venv:

    make check