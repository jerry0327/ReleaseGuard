from __future__ import annotations

import unittest

from tests.npm_provenance_fixtures import *  # noqa: F403


class NpmProvenanceTests(unittest.TestCase):
    def test_valid_v1_provenance_passes(self) -> None:
        result = verify(FakeRunner())
        self.assertEqual(result.decision, "PASS")
        self.assertEqual(result.findings, ())
        self.assertEqual(result.evidence.status, "verified")
        self.assertEqual(result.evidence.repository, REPOSITORY)
        self.assertEqual(result.evidence.workflow, WORKFLOW)
        self.assertEqual(result.evidence.commit_sha, COMMIT)
        self.assertIn(NPM_PUBLISH_V01, result.evidence.publish_attestation_types)

    def test_valid_v02_provenance_passes(self) -> None:
        result = verify(FakeRunner(audit=audit_payload(provenance=provenance_v02())))
        self.assertEqual(result.decision, "PASS")
        self.assertEqual(result.evidence.predicate_type, SLSA_V02)

    def test_release_attestation_is_accepted_as_publish_evidence(self) -> None:
        provenance = provenance_v1()
        release = publish_statement(IN_TOTO_RELEASE_V01)
        audit = {
            "invalid": [],
            "missing": [],
            "verified": [
                {
                    "name": PACKAGE,
                    "version": VERSION,
                    "attestationBundles": [
                        {"predicateType": SLSA_V1, "bundle": envelope(provenance)},
                        {
                            "predicateType": IN_TOTO_RELEASE_V01,
                            "bundle": envelope(release),
                        },
                    ],
                }
            ],
        }
        result = verify(FakeRunner(audit=audit))
        self.assertEqual(result.decision, "PASS")
        self.assertIn(IN_TOTO_RELEASE_V01, result.evidence.publish_attestation_types)

    def test_missing_provenance_is_distinct(self) -> None:
        result = verify(FakeRunner(manifest_payload=manifest(attestations=False)))
        ids = {finding.rule_id for finding in result.findings}
        self.assertEqual(result.evidence.status, "missing")
        self.assertIn("RG015", ids)
        self.assertEqual(result.decision, "BLOCK")
        self.assertFalse(any(call[0][1] == "install" for call in FakeRunner().calls))

    def test_invalid_attestation_is_distinct(self) -> None:
        invalid = [
            {
                "name": PACKAGE,
                "version": VERSION,
                "code": "EATTESTATIONVERIFY",
            }
        ]
        result = verify(FakeRunner(audit=audit_payload(invalid=invalid), audit_returncode=1))
        self.assertEqual(result.evidence.status, "invalid")
        self.assertEqual(result.findings[0].rule_id, "RG016")
        self.assertEqual(result.decision, "BLOCK")

    def test_unrelated_invalid_dependency_does_not_replace_verified_target(self) -> None:
        invalid = [{"name": "other", "version": "1.0.0", "code": "EATTESTATIONVERIFY"}]
        result = verify(FakeRunner(audit=audit_payload(invalid=invalid), audit_returncode=1))
        self.assertEqual(result.decision, "PASS")

    def test_old_npm_is_unavailable(self) -> None:
        runner = FakeRunner(npm_version="10.9.2")
        result = verify(runner, attempts=3, retry_delay=0)
        self.assertEqual(result.evidence.status, "unavailable")
        self.assertEqual(result.findings[0].rule_id, "RG017")
        self.assertEqual(len(runner.calls), 1)

    def test_trusted_publisher_is_required_by_default(self) -> None:
        result = verify(FakeRunner(manifest_payload=manifest(trusted=False)))
        self.assertIn("RG018", {finding.rule_id for finding in result.findings})

    def test_trusted_publisher_requirement_can_be_relaxed(self) -> None:
        result = verify(
            FakeRunner(manifest_payload=manifest(trusted=False)),
            require_trusted_publisher=False,
        )
        self.assertNotIn("RG018", {finding.rule_id for finding in result.findings})
        self.assertEqual(result.decision, "PASS")

    def test_repository_mismatch_blocks(self) -> None:
        result = verify(
            FakeRunner(
                audit=audit_payload(
                    provenance=provenance_v1(repository="https://github.com/attacker/repo")
                )
            )
        )
        self.assertIn("RG019", {finding.rule_id for finding in result.findings})

    def test_workflow_mismatch_blocks(self) -> None:
        result = verify(
            FakeRunner(
                audit=audit_payload(
                    provenance=provenance_v1(workflow=".github/workflows/other.yml")
                )
            )
        )
        self.assertIn("RG020", {finding.rule_id for finding in result.findings})

    def test_commit_mismatch_blocks(self) -> None:
        result = verify(
            FakeRunner(audit=audit_payload(provenance=provenance_v1(commit="c" * 40)))
        )
        self.assertIn("RG021", {finding.rule_id for finding in result.findings})

    def test_ref_mismatch_is_high(self) -> None:
        result = verify(
            FakeRunner(
                audit=audit_payload(
                    provenance=provenance_v1(ref="refs/heads/main")
                )
            )
        )
        matching = [finding for finding in result.findings if finding.rule_id == "RG022"]
        self.assertEqual(matching[0].severity, "high")

    def test_builder_mismatch_blocks(self) -> None:
        result = verify(
            FakeRunner(
                audit=audit_payload(
                    provenance=provenance_v1(builder="https://example.invalid/builder")
                )
            )
        )
        self.assertIn("RG023", {finding.rule_id for finding in result.findings})

    def test_malformed_dsse_is_reported(self) -> None:
        audit = audit_payload()
        verified = audit["verified"]
        assert isinstance(verified, list)
        record = verified[0]
        assert isinstance(record, dict)
        bundles = record["attestationBundles"]
        assert isinstance(bundles, list)
        first = bundles[0]
        assert isinstance(first, dict)
        bundle = first["bundle"]
        assert isinstance(bundle, dict)
        envelope_obj = bundle["dsseEnvelope"]
        assert isinstance(envelope_obj, dict)
        envelope_obj["payload"] = "not base64!"
        result = verify(FakeRunner(audit=audit))
        self.assertIn("RG024", {finding.rule_id for finding in result.findings})

    def test_missing_publish_attestation_is_high(self) -> None:
        result = verify(FakeRunner(audit=audit_payload(include_publish=False)))
        self.assertIn("RG025", {finding.rule_id for finding in result.findings})
        self.assertEqual(result.decision, "BLOCK")

    def test_retry_after_registry_propagation(self) -> None:
        first_manifest = manifest(attestations=False)
        second_manifest = manifest(attestations=True)

        class PropagatingRunner(FakeRunner):
            def __init__(self):
                super().__init__()
                self.views = 0

            def __call__(self, argv, cwd, env, timeout):
                if len(argv) > 1 and argv[1] == "view":
                    self.views += 1
                    self.manifest_payload = first_manifest if self.views == 1 else second_manifest
                return super().__call__(argv, cwd, env, timeout)

        runner = PropagatingRunner()
        sleeps: list[float] = []
        result = verify(runner, attempts=2, retry_delay=0.25, sleeper=sleeps.append)
        self.assertEqual(result.decision, "PASS")
        self.assertEqual(result.evidence.attempts, 2)
        self.assertEqual(sleeps, [0.25])


if __name__ == "__main__":
    unittest.main()
