#!/usr/bin/env python3
"""
Root Repository Invariant and Continuous Assurance Checker.

This script enforces repository-level invariants:
1. Prohibition of emojis across all tracked repository content (Rule 15).
2. Confidentiality boundaries: local private instruction files and credentials must never be tracked (Rule 4 & 5).
3. Architectural isolation: core headless crates must not declare GUI or cloud AI dependencies (Rule 6 & 10).
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
    ".pdf", ".bin", ".tar", ".gz", ".zip", ".qcow2"
}

# Forbidden dependency keywords in headless core crates
FORBIDDEN_CORE_DEPENDENCIES = {
    "gtk4", "libadwaita", "gtk", "adw", "gdk",
    "openai", "anthropic", "langchain", "ollama",
    "reqwest", "ureq", "hyper"
}

FORBIDDEN_TRACKED_PATTERNS = [
    re.compile(r"^AGENTS\.md$"),
    re.compile(r"^.*\.pem$"),
    re.compile(r"^.*\.key$"),
    re.compile(r"^.*\.pfx$"),
    re.compile(r"^\.env.*$"),
    re.compile(r"^.*oauth_creds\.json$"),
    re.compile(r"^.*transcript.*\.jsonl$")
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

    if all_violations:
        print("\nContinuous Assurance Violations:")
        for v in all_violations:
            print(f"  - {v}")
        return 1

    print("\nAll repository invariants verified successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
