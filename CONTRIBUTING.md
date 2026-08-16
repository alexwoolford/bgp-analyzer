# Contributing

```bash
cargo fmt
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

Or: `just check` if you have [just](https://github.com/casey/just) installed.

Prefer small PRs. Keep research/eval corpora and large downloads out of git (`data/`, `private-research/`).
