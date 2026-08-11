from __future__ import annotations

import unittest

from releaseguard.config import PolicyConfig
from releaseguard.models import Change, ScanResult
from releaseguard.rules import run_rules


class RuleTests(unittest.TestCase):
    def test_install_hook_is_critical_and_blocks(self) -> None:
        changes = [Change(path="package.json", status="M")]
        docs = {
            ("base", "package.json"): {"name": "demo", "version": "1.0.0"},
            ("head", "package.json"): {
                "name": "demo",
                "version": "1.0.0",
                "scripts": {"postinstall": "node payload.js"},
            },
        }
        findings = run_rules(changes, PolicyConfig(), "base", "head", reader=lambda ref, path: docs.get((ref, path)))
        self.assertTrue(any(item.rule_id == "RG004" and item.severity == "critical" for item in findings))
        result = ScanResult("base", "head", tuple(findings), 1, "critical", "0.2.0")
        self.assertTrue(result.blocked)
        self.assertEqual(result.score, 100)

    def test_remote_dependency_is_critical(self) -> None:
        changes = [Change(path="package.json", status="M")]
        docs = {
            ("base", "package.json"): {"dependencies": {}},
            ("head", "package.json"): {"dependencies": {"leftpad": "https://example.invalid/pkg.tgz"}},
        }
        findings = run_rules(changes, PolicyConfig(), "base", "head", reader=lambda ref, path: docs.get((ref, path)))
        self.assertTrue(any(item.rule_id == "RG006" for item in findings))

    def test_registry_dependency_is_high_not_critical(self) -> None:
        changes = [Change(path="package.json", status="M"), Change(path="package-lock.json", status="M")]
        docs = {
            ("base", "package.json"): {"dependencies": {}},
            ("head", "package.json"): {"dependencies": {"leftpad": "1.3.0"}},
        }
        findings = run_rules(changes, PolicyConfig(), "base", "head", reader=lambda ref, path: docs.get((ref, path)))
        matching = [item for item in findings if item.rule_id == "RG007"]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0].severity, "high")
        self.assertFalse(any(item.severity == "critical" for item in findings))

    def test_version_bump_without_changelog_is_medium(self) -> None:
        changes = [Change(path="package.json", status="M")]
        docs = {
            ("base", "package.json"): {"version": "1.0.0"},
            ("head", "package.json"): {"version": "1.1.0"},
        }
        findings = run_rules(changes, PolicyConfig(), "base", "head", reader=lambda ref, path: docs.get((ref, path)))
        self.assertTrue(any(item.rule_id == "RG009" and item.severity == "medium" for item in findings))

    def test_protected_path_is_high(self) -> None:
        findings = run_rules(
            [Change(path=".github/workflows/release.yml", status="M")],
            PolicyConfig(),
            "base",
            "head",
            reader=lambda *_: None,
        )
        self.assertTrue(any(item.rule_id == "RG001" and item.severity == "high" for item in findings))

    def test_binary_allowlist(self) -> None:
        allowed = [Change(path="assets/logo.png", status="M", is_binary=True)]
        blocked = [Change(path="bin/payload", status="A", is_binary=True)]
        self.assertFalse(any(item.rule_id == "RG002" for item in run_rules(allowed, PolicyConfig(), "base", "head", reader=lambda *_: None)))
        self.assertTrue(any(item.rule_id == "RG002" for item in run_rules(blocked, PolicyConfig(), "base", "head", reader=lambda *_: None)))

    def test_executable_bit_is_high(self) -> None:
        changes = [Change(path="scripts/run.sh", status="M", old_mode="100644", new_mode="100755")]
        findings = run_rules(changes, PolicyConfig(), "base", "head", reader=lambda *_: None)
        self.assertTrue(any(item.rule_id == "RG003" for item in findings))

    def test_high_findings_do_not_reach_critical_score_band(self) -> None:
        changes = [
            Change(path=".github/workflows/release.yml", status="M"),
            Change(path="bin/tool", status="A", is_binary=True),
        ]
        findings = run_rules(changes, PolicyConfig(), "base", "head", reader=lambda *_: None)
        result = ScanResult("base", "head", tuple(findings), 2, "critical", "0.2.0")
        self.assertFalse(result.blocked)
        self.assertLess(result.score, 100)
        self.assertGreaterEqual(result.score, 70)


if __name__ == "__main__":
    unittest.main()
