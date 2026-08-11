from __future__ import annotations

import hashlib
import unittest

from releaseguard.models import Finding, NpmProvenanceEvidence, NpmVerificationResult, ScanResult
from releaseguard.report import npm_markdown_summary
from releaseguard.sarif import npm_sarif_payload, sarif_payload


def result(*findings: Finding) -> NpmVerificationResult:
    evidence = NpmProvenanceEvidence(
        status="verified",
        verifier="npm audit signatures --json --include-attestations",
        npm_version="11.19.0",
        registry="https://registry.npmjs.org",
        package="@acme/widget",
        version="1.2.3",
        repository="acme/widget",
        workflow=".github/workflows/publish.yml",
        commit_sha="a" * 40,
        ref="refs/tags/v1.2.3",
        builder_id="https://github.com/actions/runner/github-hosted",
        invocation_id="https://github.com/acme/widget/actions/runs/1/attempts/1",
    )
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
        findings=tuple(findings),
        fail_on="high",
        tool_version="0.3.0",
        evidence=evidence,
    )


class NpmReportingTests(unittest.TestCase):
    def test_markdown_pass_summary_has_identity(self) -> None:
        summary = npm_markdown_summary(result())
        self.assertIn("ReleaseGuard npm provenance: PASS", summary)
        self.assertIn("acme/widget", summary)
        self.assertIn(".github/workflows/publish.yml", summary)

    def test_npm_report_uses_json_native_arrays(self) -> None:
        payload = result().to_dict()
        self.assertIsInstance(payload["evidence"]["verified_attestation_types"], list)
        self.assertIsInstance(payload["evidence"]["publish_attestation_types"], list)

    def test_repository_scan_fingerprint_v1_remains_compatible(self) -> None:
        finding = Finding("RG001", "high", "Workflow changed", "detail", ".github/workflows/release.yml")
        scan = ScanResult("a", "b", (finding,), 1, "critical", "0.3.0")
        fingerprint = sarif_payload(scan)["runs"][0]["results"][0]["partialFingerprints"]["releaseguard/v1"]
        material = "\0".join(
            (finding.rule_id, finding.path or "", finding.title, finding.detail)
        )
        self.assertEqual(fingerprint, hashlib.sha256(material.encode()).hexdigest())

    def test_sarif_has_purl_and_stable_fingerprint(self) -> None:
        finding = Finding(
            "RG019",
            "critical",
            "Repository mismatch",
            "detail",
            "npm-registry",
            "fix",
        )
        first = npm_sarif_payload(result(finding))
        second = npm_sarif_payload(result(finding))
        sarif_result = first["runs"][0]["results"][0]
        self.assertEqual(first["version"], "2.1.0")
        self.assertEqual(sarif_result["ruleId"], "RG019")
        self.assertEqual(
            sarif_result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "pkg:npm/%40acme/widget@1.2.3",
        )
        self.assertEqual(
            sarif_result["partialFingerprints"],
            second["runs"][0]["results"][0]["partialFingerprints"],
        )


if __name__ == "__main__":
    unittest.main()
