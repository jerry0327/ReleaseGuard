from __future__ import annotations

import os
from unittest import mock
import unittest

from tests.npm_provenance_fixtures import *  # noqa: F403
from releaseguard.npm_provenance import _safe_detail


class NpmProvenanceTests(unittest.TestCase):
    def test_install_is_script_safe_and_auth_is_removed(self) -> None:
        runner = FakeRunner()
        with mock.patch.dict(
            os.environ,
            {
                "NODE_AUTH_TOKEN": "secret",
                "GITHUB_TOKEN": "github-secret",
                "NODE_OPTIONS": "--require /tmp/evil.js",
                "NPM_CONFIG_FOO": "bar",
            },
            clear=False,
        ):
            result = verify(runner)
        self.assertEqual(result.decision, "PASS")
        install_call = next(call for call in runner.calls if call[0][1] == "install")
        args, _, env, _ = install_call
        self.assertIn("--ignore-scripts", args)
        self.assertIn("--bin-links=false", args)
        self.assertNotIn("NODE_AUTH_TOKEN", env)
        self.assertNotIn("GITHUB_TOKEN", env)
        self.assertNotIn("NODE_OPTIONS", env)
        self.assertNotIn("NPM_CONFIG_FOO", env)
        self.assertEqual(env["NPM_CONFIG_IGNORE_SCRIPTS"], "true")

    def test_report_does_not_store_raw_bundle(self) -> None:
        payload = verify(FakeRunner()).to_dict()
        serialized = json.dumps(payload)
        self.assertNotIn("dsseEnvelope", serialized)
        self.assertNotIn("verificationMaterial", serialized)
        self.assertEqual(payload["report_type"], "npm-provenance")

    def test_npm_12_single_manifest_array_is_supported(self) -> None:
        result = verify(FakeRunner(npm_version="12.0.0", manifest_payload=[manifest()]))
        self.assertEqual(result.decision, "PASS")

    def test_compatible_v1_and_v02_statements_are_accepted(self) -> None:
        v1 = provenance_v1()
        v02 = provenance_v02()
        publish = publish_statement()
        audit = {
            "invalid": [],
            "missing": [],
            "verified": [
                {
                    "name": PACKAGE,
                    "version": VERSION,
                    "attestationBundles": [
                        {"predicateType": SLSA_V02, "bundle": envelope(v02)},
                        {"predicateType": SLSA_V1, "bundle": envelope(v1)},
                        {"predicateType": NPM_PUBLISH_V01, "bundle": envelope(publish)},
                    ],
                }
            ],
        }
        result = verify(FakeRunner(audit=audit))
        self.assertEqual(result.decision, "PASS")
        self.assertEqual(result.evidence.predicate_type, SLSA_V1)

    def test_trusted_publisher_requires_oidc_configuration_id(self) -> None:
        payload = manifest()
        npm_user = payload["_npmUser"]
        assert isinstance(npm_user, dict)
        npm_user["trustedPublisher"] = {"id": "github"}
        result = verify(FakeRunner(manifest_payload=payload))
        self.assertIn("RG018", {finding.rule_id for finding in result.findings})

    def test_evidence_urls_drop_credentials_query_and_fragment(self) -> None:
        payload = manifest()
        dist = payload["dist"]
        assert isinstance(dist, dict)
        dist["tarball"] = "https://user:secret@registry.example.test/pkg.tgz?token=secret#part"
        attestations = dist["attestations"]
        assert isinstance(attestations, dict)
        attestations["url"] = "https://registry.example.test/attestations?id=secret#part"
        result = verify(FakeRunner(manifest_payload=payload))
        self.assertEqual(result.evidence.tarball_url, "https://registry.example.test/pkg.tgz")
        self.assertEqual(result.evidence.attestation_url, "https://registry.example.test/attestations")
        serialized = json.dumps(result.to_dict())
        self.assertNotIn("secret", serialized)

    def test_subject_mismatch_is_malformed(self) -> None:
        provenance = provenance_v1()
        subjects = provenance["subject"]
        assert isinstance(subjects, list)
        subject = subjects[0]
        assert isinstance(subject, dict)
        subject["name"] = "pkg:npm/attacker@9.9.9"
        result = verify(FakeRunner(audit=audit_payload(provenance=provenance)))
        self.assertIn("RG024", {finding.rule_id for finding in result.findings})

    def test_subject_digest_must_be_canonical_sha512_hex(self) -> None:
        provenance = provenance_v1()
        subjects = provenance["subject"]
        assert isinstance(subjects, list)
        subject = subjects[0]
        assert isinstance(subject, dict)
        digest = subject["digest"]
        assert isinstance(digest, dict)
        digest["sha512"] = "not-a-digest"
        result = verify(FakeRunner(audit=audit_payload(provenance=provenance)))
        self.assertIn("RG024", {finding.rule_id for finding in result.findings})

    def test_trusted_publisher_metadata_can_propagate_on_retry(self) -> None:
        first_manifest = manifest(trusted=False)
        second_manifest = manifest(trusted=True)

        class PublisherPropagationRunner(FakeRunner):
            def __init__(self):
                super().__init__()
                self.views = 0

            def __call__(self, argv, cwd, env, timeout):
                if len(argv) > 1 and argv[1] == "view":
                    self.views += 1
                    self.manifest_payload = first_manifest if self.views == 1 else second_manifest
                return super().__call__(argv, cwd, env, timeout)

        runner = PublisherPropagationRunner()
        sleeps: list[float] = []
        result = verify(runner, attempts=2, retry_delay=0.25, sleeper=sleeps.append)
        self.assertEqual(result.decision, "PASS")
        self.assertEqual(result.evidence.attempts, 2)
        self.assertEqual(sleeps, [0.25])

    def test_error_detail_redacts_credentials(self) -> None:
        detail = _safe_detail(
            "npm ERR! authorization=Bearer-secret token super-secret password=hunter2",
            "fallback",
        )
        self.assertNotIn("Bearer-secret", detail)
        self.assertNotIn("super-secret", detail)
        self.assertNotIn("hunter2", detail)

    def test_input_validation(self) -> None:
        runner = FakeRunner()
        with self.assertRaises(ValueError):
            verify_npm_package(
                "--help",
                VERSION,
                expected_repository=REPOSITORY,
                expected_workflow=WORKFLOW,
                expected_commit=COMMIT,
                runner=runner,
            )
        with self.assertRaises(ValueError):
            verify_npm_package(
                PACKAGE,
                "latest",
                expected_repository=REPOSITORY,
                expected_workflow=WORKFLOW,
                expected_commit=COMMIT,
                runner=runner,
            )
        with self.assertRaises(ValueError):
            verify_npm_package(
                PACKAGE,
                VERSION,
                expected_repository=REPOSITORY,
                expected_workflow="../publish.yml",
                expected_commit=COMMIT,
                runner=runner,
            )
        with self.assertRaises(ValueError):
            verify_npm_package(
                PACKAGE,
                VERSION,
                expected_repository=REPOSITORY,
                expected_workflow=WORKFLOW,
                expected_commit=COMMIT,
                registry="http://registry.example.com",
                runner=runner,
            )


if __name__ == "__main__":
    unittest.main()
