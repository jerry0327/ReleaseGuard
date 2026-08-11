from __future__ import annotations

import base64
import json
from pathlib import Path

from releaseguard.npm_provenance import (
    CommandResult,
    DEFAULT_BUILDER,
    IN_TOTO_RELEASE_V01,
    NPM_PUBLISH_V01,
    SLSA_V02,
    SLSA_V1,
    verify_npm_package,
)

PACKAGE = "@acme/widget"
VERSION = "1.2.3"
REPOSITORY = "acme/widget"
WORKFLOW = ".github/workflows/publish.yml"
COMMIT = "a" * 40
REF = "refs/tags/v1.2.3"

def envelope(statement: dict[str, object]) -> dict[str, object]:
    payload = base64.b64encode(json.dumps(statement).encode("utf-8")).decode("ascii")
    return {
        "dsseEnvelope": {
            "payloadType": "application/vnd.in-toto+json",
            "payload": payload,
            "signatures": [{"sig": "verified-by-fake-npm", "keyid": ""}],
        },
        "verificationMaterial": {"tlogEntries": [{"integratedTime": "1700000000"}]},
    }

def provenance_v1(
    *,
    repository: str = "https://github.com/acme/widget",
    workflow: str = WORKFLOW,
    commit: str = COMMIT,
    ref: str = REF,
    builder: str = DEFAULT_BUILDER,
) -> dict[str, object]:
    return {
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
                "buildType": "https://actions.github.io/buildtypes/workflow/v1",
                "externalParameters": {
                    "workflow": {
                        "repository": repository,
                        "path": workflow,
                        "ref": ref,
                    }
                },
                "resolvedDependencies": [
                    {
                        "uri": f"git+{repository}@{ref}",
                        "digest": {"gitCommit": commit},
                    }
                ],
            },
            "runDetails": {
                "builder": {"id": builder},
                "metadata": {
                    "invocationId": "https://github.com/acme/widget/actions/runs/123/attempts/1"
                },
            },
        },
    }

def provenance_v02() -> dict[str, object]:
    return {
        "_type": "https://in-toto.io/Statement/v0.1",
        "subject": [
            {
                "name": "pkg:npm/%40acme/widget@1.2.3",
                "digest": {"sha512": "b" * 128},
            }
        ],
        "predicateType": SLSA_V02,
        "predicate": {
            "builder": {"id": DEFAULT_BUILDER},
            "invocation": {
                "configSource": {
                    "uri": f"git+https://github.com/acme/widget@{REF}",
                    "digest": {"sha1": COMMIT},
                    "entryPoint": WORKFLOW,
                }
            },
            "metadata": {
                "buildInvocationId": "https://github.com/acme/widget/actions/runs/100"
            },
        },
    }

def publish_statement(predicate_type: str = NPM_PUBLISH_V01) -> dict[str, object]:
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": "pkg:npm/%40acme/widget@1.2.3",
                "digest": {"sha512": "b" * 128},
            }
        ],
        "predicateType": predicate_type,
        "predicate": {
            "name": PACKAGE,
            "version": VERSION,
            "registry": "https://registry.npmjs.org",
        },
    }

def manifest(*, attestations: bool = True, trusted: bool = True) -> dict[str, object]:
    dist: dict[str, object] = {
        "tarball": "https://registry.npmjs.org/@acme/widget/-/widget-1.2.3.tgz",
        "integrity": "sha512-test",
    }
    if attestations:
        dist["attestations"] = {
            "url": "https://registry.npmjs.org/-/npm/v1/attestations/@acme/widget@1.2.3",
            "provenance": {"predicateType": SLSA_V1},
        }
    payload: dict[str, object] = {
        "name": PACKAGE,
        "version": VERSION,
        "dist": dist,
        "_npmUser": {"name": "GitHub Actions"},
    }
    if trusted:
        payload["_npmUser"] = {
            "name": "GitHub Actions",
            "trustedPublisher": {"id": "github", "oidcConfigId": "oidc:test"},
        }
    return payload

def audit_payload(
    *,
    provenance: dict[str, object] | None = None,
    include_publish: bool = True,
    invalid: list[dict[str, object]] | None = None,
    missing: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    if provenance is None:
        provenance = provenance_v1()
    bundles = [
        {"predicateType": provenance["predicateType"], "bundle": envelope(provenance)}
    ]
    if include_publish:
        statement = publish_statement()
        bundles.append(
            {"predicateType": statement["predicateType"], "bundle": envelope(statement)}
        )
    verified = [
        {
            "name": PACKAGE,
            "version": VERSION,
            "location": "node_modules/@acme/widget",
            "registry": "https://registry.npmjs.org/",
            "attestations": {"url": "https://registry.npmjs.org/-/npm/v1/attestations/test"},
            "attestationBundles": bundles,
        }
    ]
    return {
        "invalid": invalid or [],
        "missing": missing or [],
        "verified": verified,
    }

class FakeRunner:
    def __init__(
        self,
        *,
        npm_version: str = "11.19.0",
        manifest_payload: object | None = None,
        audit: dict[str, object] | None = None,
        audit_returncode: int = 0,
        view_returncode: int = 0,
        install_returncode: int = 0,
    ) -> None:
        self.npm_version = npm_version
        self.manifest_payload = manifest() if manifest_payload is None else manifest_payload
        self.audit = audit or audit_payload()
        self.audit_returncode = audit_returncode
        self.view_returncode = view_returncode
        self.install_returncode = install_returncode
        self.calls: list[tuple[list[str], Path, dict[str, str], float]] = []

    def __call__(self, argv, cwd, env, timeout):
        args = list(argv)
        self.calls.append((args, cwd, dict(env), timeout))
        if args[1:] == ["--version"]:
            return CommandResult(0, self.npm_version + "\n", "")
        if len(args) > 1 and args[1] == "view":
            return CommandResult(
                self.view_returncode,
                json.dumps(self.manifest_payload) if self.view_returncode == 0 else "",
                "npm ERR! registry unavailable" if self.view_returncode else "",
            )
        if len(args) > 1 and args[1] == "install":
            return CommandResult(
                self.install_returncode,
                "",
                "npm ERR! install failed" if self.install_returncode else "",
            )
        if len(args) > 2 and args[1:3] == ["audit", "signatures"]:
            return CommandResult(self.audit_returncode, json.dumps(self.audit), "")
        raise AssertionError(f"unexpected command: {args}")

def verify(runner: FakeRunner, **kwargs):
    return verify_npm_package(
        PACKAGE,
        VERSION,
        expected_repository=REPOSITORY,
        expected_workflow=WORKFLOW,
        expected_commit=COMMIT,
        expected_ref=REF,
        runner=runner,
        timeout=30,
        **kwargs,
    )
