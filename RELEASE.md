# Release Checklist

## v0.1.0 — Initial Release

### Changes
- Rust port of satoxcoin-seeder (C++ bitcoin-seeder fork)
- Workspace with 5 crates: `seeder-core`, `dns-server`, `seeder-publish`, `seeder`, `dnsseed-publish`
- P2P network crawler with exponential-decay scoring
- Embedded raw UDP DNS server (no libunbound)
- Cloudflare DNS publisher
- MIT license

### Build
```bash
cargo build --release
cargo test
```

### Verify
- `cargo test` — all 95 tests pass
- `cargo deny check` — advisories ok, bans ok, licenses ok, sources ok
- `cargo audit` — 0 vulnerabilities

### Known Issues
- None

## Release Process

1. Update version in all Cargo.toml files:
   - `crates/seeder-core/Cargo.toml`
   - `crates/dns-server/Cargo.toml`
   - `crates/seeder-publish/Cargo.toml`
   - `bin/seeder/Cargo.toml`
   - `bin/dnsseed-publish/Cargo.toml`

2. Update version in `bin/seeder/src/main.rs` CLI name string

3. Update `RELEASE.md` with changelog for this version

4. Commit: `git commit -m "Release vX.Y.Z" && git push`

5. Tag: `git tag -a vX.Y.Z -m "vX.Y.Z" && git push --tags`

### What happens next (automated)
Pushing the `v*` tag triggers `.github/workflows/release.yml`:
- CI runs all checks and tests
- Builds `seeder` and `dnsseed-publish` binaries in release mode
- Creates a GitHub Release with auto-generated release notes
- Attaches both binaries as downloadable artifacts
