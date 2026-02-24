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
	maturin develop --features python

python-release:
	maturin develop --release --features python

lint:
	cargo clippy -- -D warnings

fmt:
	cargo fmt

check: lint test
	cargo fmt --check
