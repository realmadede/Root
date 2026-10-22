# Security Policy & Security Model

## 1. Security Philosophy & Least Privilege Guarantee

Root is designed from the ground up as a **zero-elevated-privilege utility**.

### Fundamental Guarantees:
- **No `root` or `sudo` Required**: Root executes exclusively under the privileges of the calling unprivileged user. It contains no `setuid` binaries, makes no calls to `pkexec` or `sudo`, and requests no elevated capabilities (`CAP_SYS_ADMIN`).
- **No Private Data Access**: Root does not parse, store, or transmit the textual contents of user documents, source code, private conversational histories (`transcript.jsonl`, `sessions/*.json`), or credentials (`oauth_creds.json`, `.key` files).
- **No Remote Telemetry or Cloud Dependencies**: Root makes zero network calls. It includes no analytics, tracking, or cloud dependencies.
- **Fail-Safe Invariants**: Any resource, path, or process that fails verification or cannot be definitively identified is automatically classified as `STRICTLY_PROTECTED` and left completely untouched.

---

## 2. Threat Boundaries & Security Invariants

| Domain | Invariant Enforced by Root |
|---|---|
| **Filesystem Traversal** | Uses `lstat` and `openat2` with `RESOLVE_BENEATH` and `RESOLVE_NO_SYMLINKS`. Traversal never escapes designated target roots or follows untrusted symlinks. |
| **Mount Points & Cross-FS** | Validates filesystem device IDs (`st_dev`). Halts traversal at mount boundaries. Acknowledges that cross-filesystem renames are non-atomic and enforces verified multi-step copies with rollback journals. |
| **Ownership Verification** | Independently validates `st_uid == getuid()` and process UID. Root strictly ignores resources owned by other users or the operating system. |
| **Hard Links** | Correctly distinguishes between in-place mutation hazards and safe unlinking. Tracks `st_nlink > 1` for accurate reclaimed space calculation without modifying shared graphs. |
| **Process Identity** | Validates multi-factor process identity (PID, `starttime`, executable inode, UID, `pidfd`). Recognizes that `PPID == 1` is not synonymous with abandonment. |
| **Process Signaling** | Signals are dispatched exclusively via Linux 5.4+ `pidfd_send_signal`, eliminating PID reuse race conditions. Process termination is disabled in production builds across all operating systems. |
| **Cross-Platform Filesystem** | On Windows, `FILE_FLAG_OPEN_REPARSE_POINT` isolates reparse points and directory junctions without descent. On macOS, traversal strictly preserves symlink jails via `PosixProbe`. |
| **Non-Linux Compile-Time Boundaries** | Mutation facilities (quarantine, restoration, sandbox) are gated behind `#[cfg(target_os = "linux")]`. Non-Linux builds are compiled strictly as read-only inspection utilities. |
| **Scheduler Security** | Schedulers on all platforms (systemd user timers, `~/Library/LaunchAgents`, Windows Task Scheduler) execute strictly as unprivileged user jobs without administrative elevation, validating executable paths against shell injection. |
| **Code Execution** | Root never executes scripts, package managers, or compilers located in scanned directories (no `npm run clean`, no `cargo clean`). |
| **Reversibility & Conflicts** | Deletions are executed as movements into a secure local quarantine (`~/.local/state/root/quarantine/`, permissions `0700`) with cryptographic rollback journaling. Restoration conflicts are detected and safeguarded against accidental overwrites. |
| **11-Stage Decision Pipeline** | Every candidate is evaluated through an immutable 11-stage serial pipeline before authorization, verifying production locks, platform support, tiers, scope, symlinks, target identity, parent pinning, multi-links, resource usage, consent nonces, and pre-flight state. |
| **Parent Directory Pinning** | Enforces device and inode verification on parent directories to prevent parent swap and rename races between evaluation and mutation. |
| **Streaming SHA-256 Integrity** | Computes cryptographic digests in 64 KiB chunks with continuous file descriptor validation (`fstat` == `lstat`), recording hashes prior to source unlinking. |
| **Cryptographic Consent Records** | Interactive user confirmations are bound by cryptographic nonces, target resource IDs, exact canonical paths, approved action constraints, and Unix epoch expiration timestamps (default 60s TTL). |
| **Continuous Assurance** | Automated CI checks (`.github/scripts/check_invariants.py`) verify 11 invariants including zero emojis, headless isolation, no CLI mutation commands, no non-Linux mutation exports, no unrestricted deletions, and no hidden mutation environment variables. |

For the full architectural threat model, see [docs/threat-model.md](docs/threat-model.md) and [docs/phase-11-mutation-threat-model.md](docs/phase-11-mutation-threat-model.md).
For the authorization model and transaction guarantees, see [docs/phase-11-authorization-model.md](docs/phase-11-authorization-model.md) and [docs/phase-11-transaction-guarantees.md](docs/phase-11-transaction-guarantees.md).

---

## 3. Vulnerability Reporting & Disclosure

We welcome responsible security reports from security researchers, systems programmers, and developers.

### Reporting Procedure
If you discover a security vulnerability (such as a path traversal flaw, race condition, symlink attack, or privilege issue):
1. **Do not create a public GitHub issue.**
2. Send a detailed report via encrypted email to:
   **security@bagomwa.com** (or to project lead Raphael Madede at `bagomwaraphael@gmail.com`).
3. Include:
   - Detailed description of the vulnerability.
   - Proof-of-concept (PoC) or reproduction steps.
   - Affected platform and kernel version.
   - Any proposed patch or mitigation.

### Disclosure Timeline
- **Acknowledgement**: Within 48 hours of receipt.
- **Triage & Assessment**: Within 7 business days.
- **Fix & Advisory**: We will coordinate a patch and public advisory following responsible disclosure principles, typically within 30 to 90 days depending on complexity.
