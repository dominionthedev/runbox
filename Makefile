.PHONY: build test lint fmt check env doctor clean install install-helper

build:
	cargo build --workspace

install:
	cargo build --workspace --release
	cp ./target/release/runbox /usr/local/bin/runbox

# Separate from `install` deliberately — this is the one privileged,
# security-relevant install step. runbox-helper must be root-owned with
# the setuid bit set, or every Exec/Shell invocation fails; `cargo build`
# alone never produces this state.
install-helper:
	cargo build --workspace --release
	sudo mkdir -p /usr/local/libexec
	sudo cp ./target/release/runbox-helper /usr/local/libexec/runbox-helper
	sudo chown root:wheel /usr/local/libexec/runbox-helper
	sudo chmod u+s /usr/local/libexec/runbox-helper

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
