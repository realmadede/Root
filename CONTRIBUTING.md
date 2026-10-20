# Contributing to Root

Thank you for your interest in contributing to **Root**, a secure, deterministic Linux resource management project.

Root is built with an uncompromising commitment to system security, user privacy, deterministic engineering, and world-class design.

---

## 1. Governance & Development Standards

All contributors must strictly read and comply with:
1. [SECURITY.md](SECURITY.md): Threat boundaries and vulnerability policies.
2. [docs/roadmap.md](docs/roadmap.md): The phase-based implementation plan.

### Core Non-Negotiables:
- **Phase Gating**: Never implement code outside the currently approved roadmap phase.
- **Least Privilege**: Never introduce commands requiring `root` or `sudo`.
- **Zero AI Runtimes**: Never introduce LLMs, API callers, or cloud telemetry.
- **Zero Host Risk**: Never run destructive integration tests on your host development machine; use the multi-level testing harness described in [docs/testing-strategy.md](docs/testing-strategy.md).

---

## 2. Development Setup

### Prerequisites
- **Operating System**: Linux (Kali Linux Rolling, Fedora, Debian, or Ubuntu recommended).
- **Rust Toolchain**: Rust 1.85+ stable (Rust 1.99.0 is tested on the reference machine).
- **C Compiler & Build Tools**: `gcc` / `clang`, `pkg-config`, `make`.
- **Git**: Git 2.30+ with GPG/SSH commit signing configured.

### Local Workflow
```bash
# Clone the repository
git clone https://github.com/realmadede/Root.git
cd Root

# Create a dedicated feature branch for the active phase
git checkout -b feature/phase-xx-description
```

---

## 3. Code Standards & Style

1. **Rustfmt**: All code must be formatted using the standard configuration:
   ```bash
   cargo fmt --check
   ```
2. **Clippy**: All code must pass strict linter checks with zero warnings:
   ```bash
   cargo clippy --all-targets --all-features -- -D warnings
   ```
3. **Error Handling**:
   - `unwrap()` and `expect()` are forbidden in production application paths.
   - Use explicit `Result<T, RootError>` and custom error types deriving `thiserror`.
4. **Documentation**:
   - Every public trait, struct, function, and enum must have Rustdoc comments (`///`).
   - Complex POSIX / Linux syscall invocations must be accompanied by explanatory comments detailing kernel version constraints and safety invariants.

---

## 4. Testing & Verification

1. **Unit Tests (Level 1)**: Must pass locally in under 10 seconds:
   ```bash
   cargo test
   ```
2. **Synthetic Fixtures**: Use `tempfile` and synthetic directory generators. Never hardcode personal paths (`/home/username`) in tests.
3. **Negative Safety Tests**: Every new scanner or validator must include adversarial tests (symlink loops, path traversal strings, deep recursion, permissions denial).

---

## 5. Pull Request Protocol

1. **Commit Messages**: Follow Conventional Commits format:
   - `docs(phase-00): establish threat model and cleanup policies`
   - `feat(core): implement 4-tier classification rule evaluator`
   - `test(guardian): add adversarial symlink loop test fixtures`
2. **Signed Commits**: All commits must be signed with GPG or SSH keys.
3. **Review**: Pull requests require review against the Phase Acceptance Criteria before merging.
