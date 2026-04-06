.PHONY: all build build-release clean test bench python python-release lint fmt check

all: build test

build:
	cargo build

build-release:
	cargo build --release

clean:
	cargo clean

test:
	cargo test

bench:
	cargo bench

python:
	poetry run maturin develop --manifest-path hathor-ct-crypto/Cargo.toml --features python

python-release:
	poetry run maturin develop --release --manifest-path hathor-ct-crypto/Cargo.toml --features python

lint:
	cargo clippy -- -D warnings

fmt:
	cargo fmt

check: lint test
	cargo fmt --check
