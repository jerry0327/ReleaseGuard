# Contributing to ReleaseGuard

ReleaseGuard is security-sensitive software. Contributions should favor small, auditable changes with explicit tests and threat-model reasoning.

## Local development

Requirements: Git and Python 3.11+.

```bash
git clone https://github.com/jerry0327/ReleaseGuard.git
cd ReleaseGuard
python -m unittest discover -s tests -v
python -m compileall -q releaseguard tests
python -m releaseguard --help
```

The runtime intentionally has no third-party Python dependencies. Discuss new runtime dependencies before adding them.

## Adding or changing a rule

A rule change should include:

1. a stable `RGxxx` identifier;
2. a defined attacker behavior or release invariant;
3. severity and rationale;
4. a remediation message;
5. positive and negative tests;
6. expected false positives; and
7. documentation changes when behavior or report schema changes.

Avoid rules that assign an unexplained model-generated risk score without deterministic evidence.

## Review-evidence changes

Changes to `github_evidence.py` require extra care. Tests should cover, where relevant:

- self-approval;
- stale commit approval;
- bot and untrusted reviewer exclusion;
- latest decisive state;
- base/head mismatch;
- missing or insufficient permissions;
- sanitized failures; and
- fail-closed versus warn behavior.

Never add token values, API response bodies, or review comment bodies to reports or diagnostic output.

## Output compatibility

Report schema version 2 is documented in `docs/report-schema.md` and `schemas/releaseguard-report.schema.json`.

Before 1.0, incompatible report changes require a `schema_version` increment and changelog entry. Additive optional fields do not.

SARIF fingerprints use a separately named key (`releaseguard/v1`). Changes that intentionally invalidate fingerprint identity must update that key and be documented.

## Pull requests

Keep PRs focused. Explain:

- the threat scenario or maintainer burden;
- expected false positives and tradeoffs;
- the exact checks run; and
- whether the change touches workflows, action metadata, CODEOWNERS, policy, credentials, networking, or report compatibility.

Third-party Actions in project workflows must be pinned to full commit SHAs. Dependabot is configured to propose updates; reviewers must verify the referenced release before merging.

## Reporting bugs and vulnerabilities

Ordinary bugs can use GitHub Issues. Do not include exploit details for a vulnerability in a public issue; follow [SECURITY.md](SECURITY.md).
