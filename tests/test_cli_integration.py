from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from releaseguard.cli import main


def git(directory: Path, *args: str) -> str:
    process = subprocess.run(
        ["git", *args],
        cwd=directory,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return process.stdout.strip()


class CliIntegrationTests(unittest.TestCase):
    def test_malicious_install_hook_blocks_and_writes_both_reports(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            git(directory, "init", "-q")
            git(directory, "config", "user.name", "ReleaseGuard Tests")
            git(directory, "config", "user.email", "tests@example.invalid")

            package = directory / "package.json"
            package.write_text('{"name":"fixture","version":"1.0.0"}\n', encoding="utf-8")
            git(directory, "add", "package.json")
            git(directory, "commit", "-qm", "baseline")
            base = git(directory, "rev-parse", "HEAD")

            package.write_text(
                '{"name":"fixture","version":"1.0.0","scripts":{"postinstall":"node payload.js"}}\n',
                encoding="utf-8",
            )
            git(directory, "add", "package.json")
            git(directory, "commit", "-qm", "malicious release")
            head = git(directory, "rev-parse", "HEAD")

            previous = Path.cwd()
            try:
                os.chdir(directory)
                exit_code = main(
                    [
                        "scan",
                        "--base",
                        base,
                        "--head",
                        head,
                        "--config",
                        "missing.toml",
                        "--output",
                        "report.json",
                        "--sarif-output",
                        "report.sarif",
                    ]
                )
            finally:
                os.chdir(previous)

            self.assertEqual(exit_code, 2)
            report = json.loads((directory / "report.json").read_text(encoding="utf-8"))
            sarif = json.loads((directory / "report.sarif").read_text(encoding="utf-8"))
            self.assertEqual(report["decision"], "BLOCK")
            self.assertEqual(report["schema_version"], 2)
            self.assertTrue(any(item["rule_id"] == "RG004" for item in report["findings"]))
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertTrue(any(item["ruleId"] == "RG004" for item in sarif["runs"][0]["results"]))


if __name__ == "__main__":
    unittest.main()
