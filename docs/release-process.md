# Root — Release Process & Governance

This document describes the reproducible release process, artifact generation workflow, cryptographic checksum verification, and release gate policies for Root.

---

## 1. Governance & Release Invariants

1. **Authorization Gate**: No release package or GitHub Release may be published automatically without explicit human authorization.
2. **Production Read-Only Invariant**: Production release binaries must be compiled with production mutation disabled. Experimental transaction capabilities remain restricted to isolated Level 1 synthetic fixtures.
3. **Reproducibility**: Builds must rely on committed `Cargo.lock` versions and deterministic compiler flags (`codegen-units = 1`, `lto = "thin"`).
4. **Zero AI Runtimes**: Production builds must contain zero external LLM API dependencies, cloud inference endpoints, or telemetry SDKs.
5. **Least Privilege**: Packaging scripts must never request administrative permissions at runtime or configure privileged background services.

---

## 2. Release Preparation Steps

### Step 1: Pre-Release Quality Gates
Prior to packaging, run the complete suite of automated repository quality gates:

```bash
cargo fmt --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
cargo doc --workspace --no-deps
python3 .github/scripts/check_invariants.py
```

All 250 workspace tests and 11 repository invariants must pass with zero warnings or errors.

### Step 2: Version Consistency Audit
Ensure that version strings match across all manifests:
- `Cargo.toml` (`[workspace.package].version`)
- `data/io.github.realmadede.Root.metainfo.xml` (`<release version="...">`)
- `data/debian/changelog`
- `scripts/package-deb.sh` (`VERSION`)
- `scripts/package-tarball.sh` (`VERSION`)

### Step 3: Local Package Generation
Execute the automated package builders:

```bash
# 1. Build release binaries
cargo build --release -p root-cli
cargo build --release -p root-gui --features gtk

# 2. Build Debian package
./scripts/package-deb.sh

# 3. Build Portable Linux Tarball
./scripts/package-tarball.sh

# 4. Generate SHA-256 Checksums
./scripts/generate-checksums.sh
```

### Step 4: Verification of Generated Artifacts
Confirm artifact existence in `dist/`:
- `dist/root_0.1.0-rc.1-1_amd64.deb`
- `dist/root-v0.1.0-rc.1-x86_64-unknown-linux-gnu.tar.gz`
- `dist/SHA256SUMS`

Verify package integrity and contents:
```bash
dpkg-deb -I dist/root_0.1.0-rc.1-1_amd64.deb
dpkg-deb -c dist/root_0.1.0-rc.1-1_amd64.deb
tar -ztvf dist/root-v0.1.0-rc.1-x86_64-unknown-linux-gnu.tar.gz
sha256sum -c dist/SHA256SUMS
```

---

## 3. CI/CD Release Pipeline

The GitHub Actions workflow `.github/workflows/release.yml` automates release artifact generation upon explicit trigger:
1. **Trigger**: Can be triggered manually via `workflow_dispatch` (with an optional `publish_draft` flag) or by pushing an authorized git tag matching `v*.*.*`.
2. **Quality Gate Job**: Executes invariant validation, formatting checks, Clippy, workspace tests, and documentation build on an `ubuntu-24.04` runner.
3. **Packaging Job**: Compiles release binaries with native GTK4/Libadwaita, builds the Debian package and portable tarball, computes SHA-256 checksums, and uploads them as workflow artifacts.
4. **Draft Release**: If authorized, creates a draft release containing release notes and attaches the distribution packages. Draft releases require human sign-off before being marked public.
