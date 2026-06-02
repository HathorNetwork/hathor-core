.PHONY: build build-release python python-release clean check

build:
	cargo build

build-release:
	cargo build --release

python:
	maturin develop

python-release:
	maturin develop --release

clean:
	cargo clean

check:
	cargo check
