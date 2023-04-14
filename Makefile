clippy:
	cargo clippy --fix --all-features -- -D warnings
	cargo clippy --all-features -- -D warnings

fmt:
	cargo fmt -- --emit files
