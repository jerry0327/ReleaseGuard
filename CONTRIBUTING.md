# Contributing to ReleaseGuard

ReleaseGuard is security-sensitive software. Contributions should be small, auditable, deterministic, and accompanied by tests that explain the relevant trust boundary.

## Local development

Requirements: Git and Python 3.11+.

```bash
git clone https://github.com/jerry0327/ReleaseGuard.git
cd ReleaseGuard
python -m unittest discover -s tests -v
python -m compileall -q releaseguard tests
python -m releaseguard --help
```

The Python runtime intentionally has no third-party dependencies. Discuss new runtime dependencies before adding them.

## Adding or changing a rule

A rule change should include:

1. a stable `RGxxx` identifier;
2. the attacker behavior or release invariant;
3. severity and rationale;
4. remediation;
5. positive and negative tests;
6. expected false positives; and
7. documentation and schema updates where behavior changes.

Avoid rules that assign an unexplained model-generated risk score without deterministic evidence.

## Review-evidence changes

Changes to `github_evidence.py` should test self-approval, stale approval, bot and untrusted reviewer exclusion, latest decisive state, base/head mismatch, missing permissions, sanitized failures, and fail-closed versus warn behavior.

Never add token values, API response bodies, or review comment bodies to reports.

## npm provenance changes

Changes to `npm_provenance.py`, `actions/verify-npm`, or npm report schemas should test, where relevant:

- exact package and version validation;
- supported SLSA statement versions;
- target package filtering;
- missing, invalid, unavailable, and verified states;
- repository, workflow, commit, ref, builder, and subject identity;
- trusted-publisher and registry publish-attestation behavior;
- credential stripping and `NODE_OPTIONS` isolation;
- lifecycle-script and bin-link suppression;
- output, payload, timeout, retry, and bundle-count limits;
- registry propagation; and
- absence of raw Sigstore bundles or credentials in reports.

Do not replace npm's maintained Sigstore verifier with a partial home-grown cryptographic implementation. Claim parsing may occur only after the delegated verifier has identified the bundle as verified.

## Output compatibility

Repository scan report schema version 2 is documented in `docs/report-schema.md`. npm provenance report schema version 1 is documented in `docs/npm-provenance-report.md`.

Before 1.0, incompatible report changes require a `schema_version` increment and changelog entry. Additive optional fields do not. SARIF fingerprints are independently namespaced; an intentional fingerprint break requires a new namespace and documentation.

## Pull requests

Explain:

- the threat scenario or maintainer burden;
- expected false positives and tradeoffs;
- exact checks run;
- whether the change touches workflows, action metadata, CODEOWNERS, policy, credentials, networking, parsers, registry behavior, or report compatibility; and
- why any new third-party dependency is necessary.

Third-party Actions in project workflows and examples should be pinned to full commit SHAs. Dependabot may propose updates, but reviewers must verify the referenced release before merging.

## Bugs and vulnerabilities

Ordinary bugs can use GitHub Issues. Do not include exploit details for a vulnerability in a public issue; follow [SECURITY.md](SECURITY.md).
