from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from unittest import mock
import unittest

from releaseguard.cli import _workflow_from_environment, main
from releaseguard.models import NpmProvenanceEvidence, NpmVerificationResult


def passing_result() -> NpmVerificationResult:
    return NpmVerificationResult(
        package="@acme/widget",
        version="1.2.3",
        registry="https://registry.npmjs.org",
        expected_repository="acme/widget",
        expected_workflow=".github/workflows/publish.yml",
        expected_commit="a" * 40,
        expected_ref="refs/tags/v1.2.3",
        expected_builder="https://github.com/actions/runner/github-hosted",
        require_trusted_publisher=True,
        findings=(),
        fail_on="high",
        tool_version="0.3.0",
        evidence=NpmProvenanceEvidence(
            status="verified",
            verifier="npm audit signatures --json --include-attestations",
            npm_version="11.19.0",
            registry="https://registry.npmjs.org",
            package="@acme/widget",
            version="1.2.3",
            repository="acme/widget",
            workflow=".github/workflows/publish.yml",
            commit_sha="a" * 40,
        ),
    )


class CliNpmTests(unittest.TestCase):
    def test_workflow_path_is_derived_from_github_workflow_ref(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "GITHUB_REPOSITORY": "acme/widget",
                "GITHUB_WORKFLOW_REF": "acme/widget/.github/workflows/publish.yml@refs/tags/v1.2.3",
            },
            clear=False,
        ):
            self.assertEqual(_workflow_from_environment(), ".github/workflows/publish.yml")

    def test_verify_npm_command_writes_both_reports_and_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            output = directory / "report.json"
            sarif = directory / "report.sarif"
            github_output = directory / "github-output"
            summary = directory / "summary"
            with mock.patch("releaseguard.cli.verify_npm_package", return_value=passing_result()), mock.patch.dict(
                os.environ,
                {"GITHUB_OUTPUT": str(github_output), "GITHUB_STEP_SUMMARY": str(summary)},
                clear=False,
            ):
                code = main(
                    [
                        "verify-npm",
                        "@acme/widget",
                        "--version",
                        "1.2.3",
                        "--repository",
                        "acme/widget",
                        "--workflow",
                        ".github/workflows/publish.yml",
                        "--commit",
                        "a" * 40,
                        "--ref",
                        "refs/tags/v1.2.3",
                        "--output",
                        str(output),
                        "--sarif-output",
                        str(sarif),
                    ]
                )
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output.read_text())["report_type"], "npm-provenance")
            self.assertEqual(json.loads(sarif.read_text())["version"], "2.1.0")
            self.assertIn("decision=PASS", github_output.read_text())
            self.assertIn("cryptographic-status=verified", github_output.read_text())
            self.assertIn("ReleaseGuard npm provenance: PASS", summary.read_text())

    def test_missing_identity_inputs_return_operational_error(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            code = main(["verify-npm", "@acme/widget", "--version", "1.2.3"])
        self.assertEqual(code, 3)


if __name__ == "__main__":
    unittest.main()
