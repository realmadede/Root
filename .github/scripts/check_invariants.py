#!/usr/bin/env python3
"""
Root Repository Invariant and Continuous Assurance Checker.

This script enforces repository-level invariants:
1. Prohibition of emojis across all tracked repository content (Rule 15).
2. Confidentiality boundaries: local private instruction files and credentials must never be tracked (Rule 4 & 5).
3. Architectural isolation: core headless crates must not declare GUI or cloud AI dependencies (Rule 6 & 10).
4. No production mutation entry points in CLI.
5. No non-Linux mutation implementations exported in root-platform.
6. No unrestricted filesystem deletion calls outside authorized transaction rollback or isolated synthetic fixtures.
7. No mutation paths reachable from live monitor or scheduler modules.
8. No hidden mutation-enabling or safety-bypassing environment variables.
9. Privileged service installation prohibition (user-level only).
10. Strict Guardian authorization bypass prevention.
11. Untracked repository hygiene.
"""

import os
import re
import subprocess
import sys

# Emoji and pictograph regex covering Unicode emoji ranges
EMOJI_PATTERN = re.compile(
    r"[\U0001F600-\U0001F64F"  # Emoticons
    r"\U0001F300-\U0001F5FF"  # Miscellaneous Symbols and Pictographs
    r"\U0001F680-\U0001F6FF"  # Transport and Map Symbols
    r"\U0001F1E0-\U0001F1FF"  # Regional Indicator Symbols (Flags)
    r"\U0001F900-\U0001F9FF"  # Supplemental Symbols and Pictographs
    r"\U0001FA70-\U0001FAFF"  # Symbols and Pictographs Extended-A
    r"\U00002702-\U000027B0"  # Dingbats
    r"\U0001F004\U0001F0CF]"   # Game symbols
)

# Binary or media file extensions excluded from text scanning
MEDIA_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
    ".pdf", ".bin", ".tar", ".gz", ".deb", ".zip", ".qcow2"
}

# Forbidden dependency keywords in headless core crates
FORBIDDEN_CORE_DEPENDENCIES = {
    "gtk4", "libadwaita", "gtk", "adw", "gdk",
    "openai", "anthropic", "langchain", "ollama",
    "reqwest", "ureq", "hyper"
}

FORBIDDEN_TRACKED_PATTERNS = [
    re.compile(r"(?:^|/)AGENTS\.md$"),
    re.compile(r"^.*\.pem$"),
    re.compile(r"^.*\.key$"),
    re.compile(r"^.*\.pfx$"),
    re.compile(r"^\.env.*$"),
    re.compile(r"^.*oauth_creds\.json$"),
    re.compile(r"^.*transcript.*\.jsonl$")
]

PROHIBITED_CLI_SUBCOMMANDS = {
    "clean", "delete", "purge", "quarantine", "destroy", "kill", "restore"
}

PROHIBITED_CLI_FLAGS = {
    "clean", "delete", "purge", "quarantine", "destroy", "kill", "restore"
}

MUTATION_KEYWORD_PATTERNS = [
    re.compile(r"\bfn\s+quarantine\b"),
    re.compile(r"\bfn\s+delete\b"),
    re.compile(r"\bfn\s+restore\b"),
    re.compile(r"\bfn\s+terminate_process\b")
]


def get_candidate_files() -> list[str]:
    """Return all tracked and untracked repository files (excluding ignored files)."""
    result = subprocess.run(
        ["git", "ls-files", "-c", "-o", "--exclude-standard"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True
    )
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def check_emoji_prohibition(files: list[str]) -> list[str]:
    """Verify that no tracked file contains emoji characters."""
    violations = []
    for file_path in files:
        _, ext = os.path.splitext(file_path)
        if ext.lower() in MEDIA_EXTENSIONS:
            continue
        if not os.path.isfile(file_path):
            continue

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line_idx, line in enumerate(f, start=1):
                    matches = EMOJI_PATTERN.findall(line)
                    if matches:
                        unique_matches = "".join(sorted(set(matches)))
                        violations.append(
                            f"{file_path}:{line_idx}: Contains prohibited emoji: '{unique_matches}'"
                        )
        except UnicodeDecodeError:
            continue

    return violations


def check_confidentiality(files: list[str]) -> list[str]:
    """Verify that private instructions and sensitive files are never tracked in Git."""
    violations = []
    for file_path in files:
        for pattern in FORBIDDEN_TRACKED_PATTERNS:
            if pattern.search(file_path):
                violations.append(
                    f"Confidential or sensitive file tracked in Git: {file_path}"
                )
    return violations


def check_core_architecture_isolation() -> list[str]:
    """Verify that core engine crates remain strictly headless and free from AI runtimes."""
    violations = []
    core_crate_manifests = [
        "crates/root-core/Cargo.toml",
        "crates/root-guardian/Cargo.toml",
        "crates/root-platform/Cargo.toml"
    ]

    for manifest in core_crate_manifests:
        if not os.path.isfile(manifest):
            continue

        with open(manifest, "r", encoding="utf-8") as f:
            content = f.read().lower()

        for forbidden in FORBIDDEN_CORE_DEPENDENCIES:
            if re.search(rf"\b{re.escape(forbidden)}\b", content):
                violations.append(
                    f"{manifest}: Violates headless isolation by referencing prohibited dependency: '{forbidden}'"
                )

    return violations


def check_no_production_mutation_cli() -> list[str]:
    """Verify that the production CLI does not export mutation subcommands or mutation flags."""
    violations = []
    cli_args_file = "crates/root-cli/src/args.rs"
    if not os.path.isfile(cli_args_file):
        violations.append(f"Missing expected CLI args file: {cli_args_file}")
        return violations

    with open(cli_args_file, "r", encoding="utf-8") as f:
        content = f.read()

    # Find the Commands enum definition
    enum_match = re.search(r"pub\s+enum\s+Commands\s*\{(.*?)\n\}", content, re.DOTALL)
    if not enum_match:
        violations.append(f"{cli_args_file}: Unable to locate 'pub enum Commands' definition")
        return violations

    enum_body = enum_match.group(1)
    for variant in PROHIBITED_CLI_SUBCOMMANDS:
        pattern = rf"\b{variant}\b"
        if re.search(pattern, enum_body, re.IGNORECASE):
            violations.append(
                f"{cli_args_file}: Commands enum exports prohibited production mutation variant: '{variant}'"
            )

    # Check for prohibited CLI flags across all argument structs
    for flag in PROHIBITED_CLI_FLAGS:
        flag_pattern = rf"\b(?:pub\s+)?{flag}\s*:\s*bool\b"
        if re.search(flag_pattern, content, re.IGNORECASE):
            violations.append(
                f"{cli_args_file}: CLI args struct exports prohibited mutation flag: '{flag}'"
            )

    return violations


def check_no_non_linux_mutation_exports() -> list[str]:
    """Verify that macOS and Windows platform modules do not export mutation functions."""
    violations = []
    target_dirs = [
        "crates/root-platform/src/macos",
        "crates/root-platform/src/windows"
    ]

    for d in target_dirs:
        if not os.path.isdir(d):
            continue
        for root_dir, _, filenames in os.walk(d):
            for filename in filenames:
                if not filename.endswith(".rs"):
                    continue
                file_path = os.path.join(root_dir, filename)
                with open(file_path, "r", encoding="utf-8") as f:
                    for line_idx, line in enumerate(f, start=1):
                        for pat in MUTATION_KEYWORD_PATTERNS:
                            if pat.search(line):
                                violations.append(
                                    f"{file_path}:{line_idx}: Exports prohibited non-Linux mutation method: '{line.strip()}'"
                                )

    return violations


def check_unrestricted_filesystem_deletion() -> list[str]:
    """Verify no unrestricted file or directory deletion calls exist in production code."""
    violations = []
    crates_dir = "crates"

    for root_dir, _, filenames in os.walk(crates_dir):
        # Exclude integration tests and tests directories
        if "/tests" in root_dir or root_dir.endswith("/tests"):
            continue

        for filename in filenames:
            if not filename.endswith(".rs"):
                continue
            file_path = os.path.join(root_dir, filename)

            # Allowed files with verified internal safe removals:
            # - scheduler.rs / launchd.rs / task_scheduler.rs (atomic temp rollback and self unit uninstall)
            # - schedule.rs in cli (removes user schedule config file upon explicit disable)
            # - transaction.rs in guardian (isolated synthetic rollback)
            allowed_stems = {"scheduler.rs", "launchd.rs", "task_scheduler.rs", "schedule.rs", "transaction.rs"}
            if os.path.basename(file_path) in allowed_stems:
                continue

            with open(file_path, "r", encoding="utf-8") as f:
                in_test_module = False
                for line_idx, line in enumerate(f, start=1):
                    if "#[cfg(test)]" in line or "mod tests" in line:
                        in_test_module = True
                    if in_test_module:
                        continue

                    if re.search(r"\b(?:fs::|std::fs::)?remove_(?:file|dir_all|dir)\s*\(", line):
                        # Direct deletion of user resources is prohibited outside approved coordinators
                        violations.append(
                            f"{file_path}:{line_idx}: Unrestricted deletion call in production code: '{line.strip()}'"
                        )

    return violations


def check_no_mutation_from_monitor_or_scheduler() -> list[str]:
    """Verify that monitor and scheduler modules do not call or import Guardian mutation structures."""
    violations = []
    crates_dir = "crates"

    prohibited_tokens = [
        "TransactionCoordinator",
        "RecoveryJournal",
        "ProposedAction::Quarantine",
        "ProposedAction::Prune"
    ]

    checked_files = set()
    for root_dir, _, filenames in os.walk(crates_dir):
        if "/tests" in root_dir or root_dir.endswith("/tests"):
            continue
        for filename in filenames:
            if not filename.endswith(".rs"):
                continue
            file_path = os.path.join(root_dir, filename)
            # Scan any file in monitor or scheduler modules
            lower_path = file_path.lower()
            if "monitor" in lower_path or "sched" in lower_path or "launchd" in lower_path:
                checked_files.add(file_path)

    for file_path in sorted(checked_files):
        with open(file_path, "r", encoding="utf-8") as f:
            for line_idx, line in enumerate(f, start=1):
                for token in prohibited_tokens:
                    if token in line:
                        violations.append(
                            f"{file_path}:{line_idx}: Monitor or scheduler invokes mutation structure: '{token}'"
                        )

    return violations


def check_no_hidden_mutation_env_vars() -> list[str]:
    """Confirm that no environment variable exists to bypass fixture mode or enable production mutation."""
    violations = []
    crates_dir = "crates"

    allowed_env_vars = {
        "HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_DATA_HOME",
        "XDG_CACHE_HOME", "XDG_RUNTIME_DIR", "NO_COLOR", "TERM",
        "COLUMNS", "LOCALAPPDATA", "CARGO_PKG_VERSION"
    }

    env_pattern = re.compile(r'(?:env::var|env::var_os|option_env!)\s*\(\s*"([^"]+)"\s*\)')

    for root_dir, _, filenames in os.walk(crates_dir):
        if "/tests" in root_dir or root_dir.endswith("/tests"):
            continue

        for filename in filenames:
            if not filename.endswith(".rs"):
                continue
            file_path = os.path.join(root_dir, filename)

            # Skip Windows environment mapping which reads arbitrary system variable names dynamically
            if "windows/environment.rs" in file_path:
                continue

            with open(file_path, "r", encoding="utf-8") as f:
                for line_idx, line in enumerate(f, start=1):
                    for match in env_pattern.finditer(line):
                        var_name = match.group(1)
                        if var_name not in allowed_env_vars:
                            violations.append(
                                f"{file_path}:{line_idx}: Undocumented environment variable read: '{var_name}'"
                            )

    return violations


def check_privileged_service_installation() -> list[str]:
    """Ensure scheduler logic only targets user-level and unprivileged contexts."""
    violations = []
    privileged_patterns = [
        re.compile(r'"/etc/systemd/system'),
        re.compile(r'"/Library/LaunchDaemons'),
        re.compile(r"<RunLevel>HighestAvailable</RunLevel>")
    ]

    checked_dirs = [
        "crates/root-platform/src/linux",
        "crates/root-platform/src/macos",
        "crates/root-platform/src/windows"
    ]

    for d in checked_dirs:
        if not os.path.isdir(d):
            continue
        for root_dir, _, filenames in os.walk(d):
            for filename in filenames:
                if not filename.endswith(".rs"):
                    continue
                file_path = os.path.join(root_dir, filename)
                with open(file_path, "r", encoding="utf-8") as f:
                    for line_idx, line in enumerate(f, start=1):
                        stripped = line.strip()
                        if stripped.startswith("//") or stripped.startswith("/*"):
                            continue
                        for pat in privileged_patterns:
                            if pat.search(line):
                                violations.append(
                                    f"{file_path}:{line_idx}: Privileged installation path detected: '{stripped}'"
                                )

    return violations


def check_guardian_bypass() -> list[str]:
    """Verify that TransactionEngine and TransactionState enforce Guardian authorization."""
    violations = []
    engine_file = "crates/root-guardian/src/engine.rs"
    if not os.path.isfile(engine_file):
        violations.append(f"Missing Guardian engine file: {engine_file}")
        return violations

    with open(engine_file, "r", encoding="utf-8") as f:
        engine_content = f.read()

    # Verify authorization evaluation and receipt extraction
    if "AuthorizationEngine::authorize" not in engine_content or "AuthorizationDecision::Authorized" not in engine_content:
        violations.append(
            f"{engine_file}: TransactionEngine must evaluate Guardian authorization and verify receipt before mutation"
        )

    transaction_file = "crates/root-guardian/src/transaction.rs"
    if not os.path.isfile(transaction_file):
        violations.append(f"Missing Guardian transaction file: {transaction_file}")
        return violations

    with open(transaction_file, "r", encoding="utf-8") as f:
        tx_content = f.read()

    if "(TransactionState::Proposed, TransactionState::Authorized)" not in tx_content:
        violations.append(
            f"{transaction_file}: TransactionState must mandate transition through Authorized state before execution"
        )

    return violations


def check_untracked_hygiene() -> list[str]:
    """Verify no untracked credentials, instruction files, or private data exist."""
    violations = []
    result = subprocess.run(
        ["git", "status", "--porcelain"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True
    )
    for line in result.stdout.splitlines():
        if line.startswith("??"):
            path = line[3:].strip()
            for pattern in FORBIDDEN_TRACKED_PATTERNS:
                if pattern.search(path):
                    violations.append(f"Untracked sensitive file detected in working tree: {path}")

    return violations


def main() -> int:
    """Run all assurance checks and report status."""
    print("Executing Continuous Assurance invariant checks...")
    try:
        candidate_files = get_candidate_files()
    except subprocess.CalledProcessError as err:
        print(f"Error determining repository files: {err}", file=sys.stderr)
        return 1

    all_violations: list[str] = []

    # 1. Emoji prohibition check
    emoji_violations = check_emoji_prohibition(candidate_files)
    if emoji_violations:
        all_violations.extend(emoji_violations)
        print(f"Emoji prohibition check: FAILED ({len(emoji_violations)} violations found)")
    else:
        print("Emoji prohibition check: PASSED (Zero emojis found)")

    # 2. Confidentiality check
    confidentiality_violations = check_confidentiality(candidate_files)
    if confidentiality_violations:
        all_violations.extend(confidentiality_violations)
        print(f"Confidentiality boundary check: FAILED ({len(confidentiality_violations)} violations found)")
    else:
        print("Confidentiality boundary check: PASSED (No private files tracked)")

    # 3. Core architecture isolation check
    isolation_violations = check_core_architecture_isolation()
    if isolation_violations:
        all_violations.extend(isolation_violations)
        print(f"Core architectural isolation check: FAILED ({len(isolation_violations)} violations found)")
    else:
        print("Core architectural isolation check: PASSED (Headless and local-only boundaries verified)")

    # 4. No production mutation entry points in CLI
    mutation_cli_violations = check_no_production_mutation_cli()
    if mutation_cli_violations:
        all_violations.extend(mutation_cli_violations)
        print(f"Production mutation CLI entry check: FAILED ({len(mutation_cli_violations)} violations found)")
    else:
        print("Production mutation CLI entry check: PASSED (Mutation subcommands prohibited)")

    # 5. No non-Linux mutation exports
    non_linux_violations = check_no_non_linux_mutation_exports()
    if non_linux_violations:
        all_violations.extend(non_linux_violations)
        print(f"Non-Linux mutation export check: FAILED ({len(non_linux_violations)} violations found)")
    else:
        print("Non-Linux mutation export check: PASSED (Zero non-Linux mutation methods)")

    # 6. No unrestricted filesystem deletion
    deletion_violations = check_unrestricted_filesystem_deletion()
    if deletion_violations:
        all_violations.extend(deletion_violations)
        print(f"Unrestricted deletion check: FAILED ({len(deletion_violations)} violations found)")
    else:
        print("Unrestricted deletion check: PASSED (Zero unrestricted deletion calls in production)")

    # 7. No mutation from monitor or scheduler
    monitor_sched_violations = check_no_mutation_from_monitor_or_scheduler()
    if monitor_sched_violations:
        all_violations.extend(monitor_sched_violations)
        print(f"Monitor/scheduler mutation isolation check: FAILED ({len(monitor_sched_violations)} violations found)")
    else:
        print("Monitor/scheduler mutation isolation check: PASSED (Monitor and scheduler are read-only)")

    # 8. No hidden mutation environment variables
    env_violations = check_no_hidden_mutation_env_vars()
    if env_violations:
        all_violations.extend(env_violations)
        print(f"Hidden mutation environment variable check: FAILED ({len(env_violations)} violations found)")
    else:
        print("Hidden mutation environment variable check: PASSED (No mutation toggle variables)")

    # 9. Privileged service installation check
    privilege_violations = check_privileged_service_installation()
    if privilege_violations:
        all_violations.extend(privilege_violations)
        print(f"Privileged service installation check: FAILED ({len(privilege_violations)} violations found)")
    else:
        print("Privileged service installation check: PASSED (Scheduler is unprivileged user-only)")

    # 10. Guardian authorization bypass check
    bypass_violations = check_guardian_bypass()
    if bypass_violations:
        all_violations.extend(bypass_violations)
        print(f"Guardian bypass check: FAILED ({len(bypass_violations)} violations found)")
    else:
        print("Guardian bypass check: PASSED (Transactions strictly require AuthorizationReceipt)")

    # 11. Untracked repository hygiene
    hygiene_violations = check_untracked_hygiene()
    if hygiene_violations:
        all_violations.extend(hygiene_violations)
        print(f"Untracked hygiene check: FAILED ({len(hygiene_violations)} violations found)")
    else:
        print("Untracked hygiene check: PASSED (Working tree clean of private files)")

    if all_violations:
        print("\nContinuous Assurance Violations:")
        for v in all_violations:
            print(f"  - {v}")
        return 1

    print("\nAll 11 repository invariants verified successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
