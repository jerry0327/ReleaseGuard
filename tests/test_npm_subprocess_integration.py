from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import tempfile
import textwrap
import unittest

from releaseguard.cli import main
from releaseguard.npm_provenance import NPM_PUBLISH_V01, SLSA_V1


class NpmSubprocessIntegrationTests(unittest.TestCase):
    def test_cli_runs_against_isolated_fake_npm_process(self) -> None:
        package = "@acme/widget"
        version = "1.2.3"
        commit = "a" * 40
        ref = "refs/tags/v1.2.3"
        workflow = ".github/workflows/publish.yml"
        provenance = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                {
                    "name": "pkg:npm/%40acme/widget@1.2.3",
                    "digest": {"sha512": "b" * 128},
                }
            ],
            "predicateType": SLSA_V1,
            "predicate": {
                "buildDefinition": {
                    "externalParameters": {
                        "workflow": {
                            "repository": "https://github.com/acme/widget",
                            "path": workflow,
                            "ref": ref,
                        }
                    },
                    "resolvedDependencies": [
                        {
                            "uri": f"git+https://github.com/acme/widget@{ref}",
                            "digest": {"gitCommit": commit},
                        }
                    ],
                },
                "runDetails": {
                    "builder": {"id": "https://github.com/actions/runner/github-hosted"},
                    "metadata": {
                        "invocationId": "https://github.com/acme/widget/actions/runs/1/attempts/1"
                    },
                },
            },
        }
        publish = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                {
                    "name": "pkg:npm/%40acme/widget@1.2.3",
                    "digest": {"sha512": "b" * 128},
                }
            ],
            "predicateType": NPM_PUBLISH_V01,
            "predicate": {"name": package, "version": version},
        }

        def bundle(statement):
            return {
                "dsseEnvelope": {
                    "payload": base64.b64encode(json.dumps(statement).encode()).decode(),
                    "payloadType": "application/vnd.in-toto+json",
                    "signatures": [{"sig": "fake"}],
                },
                "verificationMaterial": {"tlogEntries": [{"integratedTime": "1"}]},
            }

        manifest = {
            "name": package,
            "version": version,
            "dist": {
                "integrity": "sha512-test",
                "tarball": "https://registry.npmjs.org/@acme/widget/-/widget-1.2.3.tgz",
                "attestations": {
                    "url": "https://registry.npmjs.org/-/npm/v1/attestations/@acme/widget@1.2.3"
                },
            },
            "_npmUser": {
                "name": "GitHub Actions",
                "trustedPublisher": {"id": "github", "oidcConfigId": "oidc:test"},
            },
        }
        audit = {
            "invalid": [],
            "missing": [],
            "verified": [
                {
                    "name": package,
                    "version": version,
                    "attestationBundles": [
                        {"predicateType": SLSA_V1, "bundle": bundle(provenance)},
                        {"predicateType": NPM_PUBLISH_V01, "bundle": bundle(publish)},
                    ],
                }
            ],
        }

        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            fake_npm = directory / "fake-npm"
            log_path = directory / "fake-npm-log.jsonl"
            fake_npm.write_text(
                textwrap.dedent(
                    f"""\
                    #!/usr/bin/env python3
                    import json
                    import os
                    import sys

                    manifest = {manifest!r}
                    audit = {audit!r}
                    with open({str(log_path)!r}, 'a', encoding='utf-8') as handle:
                        handle.write(json.dumps({{'argv': sys.argv[1:], 'has_node_token': 'NODE_AUTH_TOKEN' in os.environ, 'has_github_token': 'GITHUB_TOKEN' in os.environ, 'npm_config_keys': sorted(k for k in os.environ if k.startswith('NPM_CONFIG_'))}}) + '\\n')
                    if sys.argv[1:] == ['--version']:
                        print('11.19.0')
                    elif sys.argv[1] == 'view':
                        print(json.dumps(manifest))
                    elif sys.argv[1] == 'install':
                        pass
                    elif sys.argv[1:3] == ['audit', 'signatures']:
                        print(json.dumps(audit))
                    else:
                        print('unexpected invocation', file=sys.stderr)
                        raise SystemExit(9)
                    """
                ),
                encoding="utf-8",
            )
            fake_npm.chmod(0o755)
            report = directory / "report.json"
            sarif = directory / "report.sarif"
            old_token = os.environ.get("NODE_AUTH_TOKEN")
            old_github_token = os.environ.get("GITHUB_TOKEN")
            try:
                os.environ["NODE_AUTH_TOKEN"] = "must-not-cross-boundary"
                os.environ["GITHUB_TOKEN"] = "must-not-cross-boundary-either"
                code = main(
                    [
                        "verify-npm",
                        package,
                        "--version",
                        version,
                        "--repository",
                        "acme/widget",
                        "--workflow",
                        workflow,
                        "--commit",
                        commit,
                        "--ref",
                        ref,
                        "--npm",
                        str(fake_npm),
                        "--output",
                        str(report),
                        "--sarif-output",
                        str(sarif),
                        "--timeout",
                        "30",
                    ]
                )
            finally:
                if old_token is None:
                    os.environ.pop("NODE_AUTH_TOKEN", None)
                else:
                    os.environ["NODE_AUTH_TOKEN"] = old_token
                if old_github_token is None:
                    os.environ.pop("GITHUB_TOKEN", None)
                else:
                    os.environ["GITHUB_TOKEN"] = old_github_token

            self.assertEqual(code, 0)
            self.assertEqual(json.loads(report.read_text())["decision"], "PASS")
            self.assertEqual(json.loads(sarif.read_text())["version"], "2.1.0")
            invocations = [json.loads(line) for line in log_path.read_text().splitlines()]
            self.assertEqual(len(invocations), 4)
            self.assertTrue(all(not item["has_node_token"] for item in invocations))
            self.assertTrue(all(not item["has_github_token"] for item in invocations))
            install = next(item for item in invocations if item["argv"][0] == "install")
            self.assertIn("--ignore-scripts", install["argv"])
            self.assertIn("--bin-links=false", install["argv"])


if __name__ == "__main__":
    unittest.main()
