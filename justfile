# Check formatting, clippy, and tests (mirrors CI).
check:
    cargo fmt --check
    cargo clippy --workspace --all-targets --locked -- -D warnings
    cargo test --workspace --locked

fmt:
    cargo fmt

test:
    cargo test --workspace --locked

release:
    cargo build -p bgp-analyzer-cli --release --locked
