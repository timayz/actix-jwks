clippy:
	cargo clippy --all-features -- -D warnings

fmt:
	cargo fmt -- --emit files
