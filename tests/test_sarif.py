from __future__ import annotations

import unittest

from releaseguard.models import Finding, ScanResult
from releaseguard.sarif import sarif_payload


class SarifTests(unittest.TestCase):
    def test_sarif_uses_version_2_1_0(self) -> None:
        result = ScanResult(
            base="a" * 40,
            head="b" * 40,
            findings=(
                Finding(
                    "RG004",
                    "critical",
                    "Install hook changed",
                    "A postinstall hook changed.",
                    "package.json",
                    "Remove it.",
                ),
            ),
            changed_files=1,
            fail_on="critical",
            tool_version="0.2.0",
        )
        payload = sarif_payload(result)
        self.assertEqual(payload["version"], "2.1.0")
        run = payload["runs"][0]
        self.assertEqual(run["tool"]["driver"]["version"], "0.2.0")
        self.assertEqual(run["results"][0]["ruleId"], "RG004")
        self.assertEqual(run["results"][0]["level"], "error")
        self.assertEqual(
            run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "package.json",
        )

    def test_fingerprint_is_stable(self) -> None:
        finding = Finding("RG001", "high", "Workflow changed", "detail", ".github/workflows/release.yml")
        result = ScanResult("a", "b", (finding,), 1, "critical", "0.2.0")
        first = sarif_payload(result)["runs"][0]["results"][0]["partialFingerprints"]
        second = sarif_payload(result)["runs"][0]["results"][0]["partialFingerprints"]
        self.assertEqual(first, second)

    def test_empty_scan_produces_valid_empty_results(self) -> None:
        result = ScanResult("a", "b", (), 0, "critical", "0.2.0")
        run = sarif_payload(result)["runs"][0]
        self.assertEqual(run["tool"]["driver"]["rules"], [])
        self.assertEqual(run["results"], [])


if __name__ == "__main__":
    unittest.main()
