#!/usr/bin/env python3
"""
Unit and regression tests for continuous assurance invariant checker.
Validates that check_invariants.py reliably detects synthetic violations and regressions.
"""

import os
import sys
import tempfile
import unittest

# Ensure current directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from check_invariants import (
    check_emoji_prohibition,
    check_confidentiality,
    PROHIBITED_CLI_SUBCOMMANDS,
    PROHIBITED_CLI_FLAGS,
    FORBIDDEN_TRACKED_PATTERNS,
)


class TestContinuousAssuranceInvariants(unittest.TestCase):
    """Verifies that assurance checks reliably detect negative fixtures."""

    def test_emoji_detection(self):
        with tempfile.NamedTemporaryFile("w+", suffix=".txt", encoding="utf-8") as f:
            # Write a smiley emoji using escaped codepoint
            f.write("Line with prohibited symbol: \U0001F600\n")
            f.flush()
            violations = check_emoji_prohibition([f.name])
            self.assertEqual(len(violations), 1, "Must detect emoji in candidate file")
            self.assertIn("Contains prohibited emoji", violations[0])

    def test_clean_file_emoji_check(self):
        with tempfile.NamedTemporaryFile("w+", suffix=".txt", encoding="utf-8") as f:
            f.write("Standard alphanumeric text and Cyrillic text: Привет мир\n")
            f.flush()
            violations = check_emoji_prohibition([f.name])
            self.assertEqual(len(violations), 0, "Clean text must produce zero violations")

    def test_confidential_file_patterns(self):
        test_paths = [
            "AGENTS.md",
            "docs/AGENTS.md",
            "cert.pem",
            "private.key",
            "wallet.pfx",
            ".env",
            ".env.production",
            "oauth_creds.json",
            "session_transcript.jsonl",
        ]
        violations = check_confidentiality(test_paths)
        self.assertEqual(len(violations), len(test_paths), "Must flag all confidential patterns")

    def test_prohibited_cli_subcommands_coverage(self):
        # Mandatory prohibited subcommands must include prune, clean, quarantine, etc.
        required_subcommands = {"clean", "delete", "purge", "quarantine", "destroy", "kill", "restore", "prune"}
        for cmd in required_subcommands:
            self.assertIn(cmd, PROHIBITED_CLI_SUBCOMMANDS, f"PROHIBITED_CLI_SUBCOMMANDS must contain '{cmd}'")
            self.assertIn(cmd, PROHIBITED_CLI_FLAGS, f"PROHIBITED_CLI_FLAGS must contain '{cmd}'")


if __name__ == "__main__":
    unittest.main()
