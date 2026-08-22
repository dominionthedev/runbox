.PHONY: build test lint fmt check env doctor clean

build:
	cargo build --workspace

install:
	cargo build --workspace --release
	cp ./target/release/runbox /usr/local/bin/runbox
	cp ./target/release/runbox-helper /usr/local/bin/runbox-helper

test:
	cargo test --workspace

lint:
	cargo clippy --workspace --all-targets -- -D warnings
	python3 scripts/check_helper_deps.py

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

check: fmt-check lint test
	@echo "All checks passed."

env:
	python3 scripts/check_env.py

clean:
	cargo clean
