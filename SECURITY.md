# Security policy

## Supported versions

ReleaseGuard is pre-1.0. Security fixes are applied to the latest development line. Users should pin Actions to reviewed commit SHAs and update only after reviewing security-relevant changes.

## Reporting a vulnerability

Prefer GitHub's **private vulnerability reporting** / Security Advisory flow for this repository when available.

If private reporting is unavailable, open a public issue containing only a request for a private security contact. Do **not** post exploit details, secrets, proof-of-concept payloads, token values, malicious package coordinates, or an unpatched bypass publicly.

A useful private report includes:

- affected ReleaseGuard version or commit;
- the policy bypass, evidence confusion, parser failure, or unsafe subprocess behavior;
- minimal reproduction steps;
- expected security boundary;
- whether credentials, registry content, GitHub metadata, or untrusted package metadata are involved; and
- any proposed mitigation.

## Security boundaries

ReleaseGuard evaluates three distinct evidence classes:

1. repository release deltas;
2. GitHub pull-request review authorization; and
3. published npm registry artifact provenance.

For npm verification, ReleaseGuard delegates cryptographic signature, certificate-chain, transparency-log, and artifact-subject verification to a supported npm CLI. ReleaseGuard then evaluates normalized claims from the target package's verified bundles. It does not treat the presence of `dist.attestations` as cryptographic proof by itself.

ReleaseGuard does not claim to secure npm, GitHub, Sigstore, runner images, operating systems, registry credentials, or every repository-administrator action. See [docs/threat-model.md](docs/threat-model.md).

## Credential handling

The pull-request gate accepts a GitHub token through `RELEASEGUARD_GITHUB_TOKEN`, `GITHUB_TOKEN`, or the root Action's `github-token` input. It does not accept the token as a CLI argument or write it to reports.

The npm provenance verifier is designed for public or anonymously readable registry artifacts in v0.3. It creates an allowlisted subprocess environment and intentionally removes npm, Node, GitHub, cloud, and other inherited credentials before invoking npm. Custom private-registry authentication is not yet supported.

Raw DSSE envelopes, certificates, transparency-log records, auth tokens, npm configuration, package files, and review bodies are not persisted in ReleaseGuard reports.
