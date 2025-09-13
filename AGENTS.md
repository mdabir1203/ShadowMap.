## Dev environment tips
- Use `find . -name "Cargo.toml" -not -path "*/target/*" | fzf | xargs dirname` to jump to any crate instantly instead of scanning directories.
- Run `cargo add --package <crate_name> <dependency>` to add dependencies to specific workspace crates so rust-analyzer can see them.
- Use `cargo new --name <crate_name> --lib crates/<crate_name>` to spin up a new library crate with proper workspace integration.
- Check the name field in each crate's Cargo.toml to confirm the right crate name—workspace root names don't matter for imports.
- Install `cargo watch -x "clippy --fix --allow-dirty" -x test -x run` for continuous feedback during development.
- Add `alias cr='cargo run'` and `alias ct='cargo test'` to your shell for faster iteration.
- Install sccache with cargo install sccache and set export RUSTC_WRAPPER=$(which sccache) to cache compiled objects locally (and remotely if configured).
- Install mold (sudo apt install mold) and set export RUSTFLAGS="-C link-arg=-fuse-ld=mold" for much faster linking; fall back to lld if mold isn’t available.

## Testing instructions
- Find the CI plan in the .github/workflows folder to understand what checks run on your code.
- Run `cargo test --workspace` to run every test across all crates in the workspace.
- From any crate root you can call `cargo test` to test just that crate—commit should pass all workspace tests before merge.
- To focus on specific tests, use the pattern: `cargo test <test_name>` or `cargo test --lib -- --nocapture <pattern>`.
- Fix any test failures, clippy warnings, or compilation errors until `cargo test --workspace` is green.
- After moving files or changing module structure, run `cargo check --workspace` to ensure all imports still work.
- Add or update tests for the code you change, even if nobody asked—focus on integration points and error paths.
- Use `cargo test --release` occasionally to catch optimization-dependent bugs that only appear in release builds.

## Performance and quality checks
- Run `cargo clippy --workspace --all-targets -- -D warnings` to catch common mistakes and enforce code quality.
- Use `cargo fmt --all` before every commit to maintain consistent formatting across the codebase.
- Run `cargo audit` to check for security vulnerabilities in your dependency tree.
- Use `cargo build --release` to verify optimized builds work correctly—debug and release can behave differently.
- Install `flamegraph` with `cargo install flamegraph` and profile with `cargo flamegraph --bin <binary>` when performance matters.
- Check binary size with `cargo bloat --release --crates` if deployment size is a concern.

## Dependency management
- Use `cargo tree --workspace --duplicates` to find duplicate dependencies that bloat compile times.
- Run `cargo outdated` to check for dependency updates, but test thoroughly after updates.
- Add `cargo deny check` to catch licensing issues and security advisories in CI.
- Prefer `--locked` flag in production builds: `cargo build --release --locked` to ensure reproducible builds.
- Use `cargo machete` to find unused dependencies that slow down builds.

## PR instructions
- Title format: `[<crate_name>] <type>: <description>`
- Always run `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace` before committing.
- Include benchmark results if you're claiming performance improvements: `cargo bench` output in PR description.
- For breaking changes, update CHANGELOG.md and bump version numbers according to semver.
- Add integration tests for new public APIs, not just unit tests—they catch more real-world issues.

## Max Dev Speed Tricks
- Cache everything: sccache local+remote.
- Link instantly: mold > lld > ld.
- Check only the crate you touched: cargo check -p <crate_name>.
- Use cargo check (type checking) way more than cargo build (linking).
- Set CARGO_TARGET_DIR=/tmp/rust-target for global dependency reuse across projects.
- Keep heavy crates gated under features; disable during iteration with cargo check --no-default-features -p <crate>.
- Find version duplication: cargo tree --workspace --duplicates.
- See stale deps: cargo outdated.
- Enforce licenses/security with cargo deny check.
- Cut wasted deps: cargo machete.
- For breaking changes: bump semver + update CHANGELOG.md.
- New public APIs → must have integration tests. Unit tests alone don’t cut it.
- Don’t waste API calls: Use mocks/stubs/sandboxes locally. CI runs live API tests at lower frequency.
- Fast feedback > Elegant excuses. Iterate in seconds, not minutes.
