# npm provenance verification

ReleaseGuard v0.3 verifies a published npm package at the registry boundary. This is separate from scanning a repository diff: the input is an exact package name and version that already exists on an npm-compatible registry.

## Security goal

The verifier answers two questions:

1. **Did a maintained npm verifier cryptographically accept the target package's registry signature and Sigstore attestations?**
2. **Do the verified SLSA claims identify the repository, workflow, commit, ref, and builder that the release process expects?**

ReleaseGuard does not treat a `dist.attestations` URL or a decoded JSON statement as proof. Claim evaluation starts only after npm reports the target package in its `verified` evidence set.

## Trust chain

```text
exact package@version
        |
        v
registry manifest ------------------------------+
        |                                       |
        | dist integrity / attestation URL      | trustedPublisher marker
        v                                       |
isolated npm install                            |
  --ignore-scripts                              |
  --bin-links=false                             |
  no inherited credentials                     |
        |                                       |
        v                                       |
npm audit signatures --json --include-attestations
        |
        | npm verifies registry signatures,
        | Sigstore bundle, certificate chain,
        | transparency-log evidence, PURL subject,
        | and package digest
        v
verified target-package bundles
        |
        v
ReleaseGuard normalizes SLSA v1 / v0.2 claims
        |
        v
repository / workflow / commit / ref / builder policy
        |
        +------------------> JSON + SARIF + PASS/BLOCK
```

The cryptographic implementation remains in the npm/Sigstore ecosystem. ReleaseGuard contributes policy binding, bounded execution, evidence normalization, stable findings, and interoperable reports.

## CLI

```bash
releaseguard verify-npm @scope/package \
  --version 1.2.3 \
  --repository owner/repository \
  --workflow .github/workflows/publish.yml \
  --commit 0123456789abcdef0123456789abcdef01234567 \
  --ref refs/tags/v1.2.3
```

Required inputs are exact and deliberately narrow:

- package names must be lowercase npm names;
- versions must be exact SemVer values, not tags or ranges;
- repositories must resolve to `github.com/owner/repository`;
- workflows must be `.github/workflows/*.yml` or `.yaml` paths;
- commits must be full 40-character Git SHAs; and
- refs, when supplied, must use `refs/heads/...` or `refs/tags/...`.

GitHub Actions supplies repository, SHA, ref, and workflow context automatically when the corresponding CLI values are omitted.

## Supported evidence

### Cryptographic verifier

`verify-npm` requires npm `11.12.0` or newer because it consumes the full bundles returned by:

```bash
npm audit signatures --json --include-attestations
```

The composite Action pins npm `11.19.0` and Node.js `24.18.1`.

### Provenance predicates

ReleaseGuard normalizes:

- SLSA provenance v1: `https://slsa.dev/provenance/v1`
- legacy SLSA provenance v0.2: `https://slsa.dev/provenance/v0.2`

When compatible v1 and v0.2 statements coexist, v1 is preferred. Conflicting source identities are rejected.

### Registry publication evidence

At least one recognized registry-side publish/release attestation is expected:

- npm publish attestation v0.1; or
- in-toto release attestation v0.1.

The registry publish/release attestation supplements build provenance. Its absence produces `RG025`.

## Trusted publishing policy

By default, ReleaseGuard also requires npm metadata to identify the version as published through GitHub trusted publishing:

```json
{
  "_npmUser": {
    "trustedPublisher": {
      "id": "github",
      "oidcConfigId": "..."
    }
  }
}
```

This marker is registry metadata rather than a replacement for Sigstore verification. ReleaseGuard requires both the `github` identifier and an OIDC configuration identifier.

A migration period can allow cryptographically valid provenance generated during token-based publication:

```bash
releaseguard verify-npm ... --allow-token-published-provenance
```

Or in the Action:

```yaml
allow-token-published-provenance: true
```

This weakens the reusable-credential policy and should be time-bounded.

## Isolated npm execution

ReleaseGuard creates a new temporary project for every attempt and installs only the exact target version. The subprocess boundary applies the following controls:

- lifecycle scripts disabled;
- package bin links disabled;
- optional dependencies omitted;
- audit/funding/update notifier disabled during installation;
- empty user and global npm configuration;
- temporary HOME, cache, and temp directories;
- allowlisted environment variables only;
- `NODE_OPTIONS` and `NODE_PATH` excluded;
- GitHub, npm, Node, cloud, and other inherited credentials excluded;
- command timeout;
- bounded stdout/stderr retention;
- bounded DSSE payload size and attestation count; and
- automatic cleanup.

Proxy and certificate variables can cross the boundary so enterprise network trust can function. Their values are not written to reports.

v0.3 intentionally supports public or anonymously readable registry artifacts. Private-registry credentials are not accepted by this verifier.

## Registry propagation

New npm versions may become visible before every metadata endpoint is consistent. The Action defaults to six attempts with ten seconds between attempts.

Retries apply to evidence that may reasonably propagate:

- package metadata or verifier temporarily unavailable;
- provenance not yet advertised;
- trusted-publisher marker not yet visible; and
- registry publish/release attestation not yet visible.

Cryptographic rejection or identity mismatch does not become a pass through retries.

## Finding semantics

| Rule | Meaning | Severity |
|---|---|---:|
| `RG015` | Provenance absent from registry metadata | High |
| `RG016` | npm rejected target signature/attestation | Critical |
| `RG017` | Required verifier unavailable | Critical |
| `RG018` | GitHub trusted-publisher marker missing/incomplete | High |
| `RG019` | Repository mismatch | Critical |
| `RG020` | Workflow mismatch | Critical |
| `RG021` | Commit mismatch | Critical |
| `RG022` | Ref mismatch | High |
| `RG023` | Builder mismatch | Critical |
| `RG024` | Verified statement structure unsupported or malformed | Critical |
| `RG025` | Registry publish/release attestation absent | High |

The default npm threshold is `high`, so every v0.3 npm finding blocks promotion unless the caller deliberately selects a weaker threshold.

## Evidence retention

The JSON report records:

- package and registry identity;
- expected identity;
- npm version and verifier status;
- registry integrity and sanitized URLs;
- trusted-publisher marker fields;
- normalized statement/predicate types;
- normalized source and builder claims; and
- findings and remediation.

It does not retain raw DSSE envelopes, signing certificates, transparency-log entries, auth tokens, npm configuration, package contents, or unbounded command output.

See [npm provenance report schema](npm-provenance-report.md).

## Known limitations

- GitHub Actions is the only source-control builder identity modeled in v0.3.
- npm is part of the verifier trust base; a compromised npm binary can invalidate the result.
- The Action pins an npm version, but its initial installation still depends on Node.js, GitHub Actions infrastructure, TLS, and the npm public registry.
- The gate verifies the selected package artifact. It does not promote unrelated transitive-dependency signature findings into ReleaseGuard rules.
- Repository/workflow identity comparison does not prove source code is benign.
- A repository or registry administrator able to disable every independent control remains outside the boundary.
- Private authenticated registries are not supported in v0.3.

## Upstream specifications and verifier references

The v0.3 implementation is grounded in the maintained ecosystem verifier and public specifications rather than a ReleaseGuard-specific cryptographic format:

- [npm trusted publishing](https://docs.npmjs.com/trusted-publishers/)
- [npm package provenance](https://docs.npmjs.com/generating-provenance-statements/)
- [npm registry signature and provenance verification](https://docs.npmjs.com/verifying-registry-signatures/)
- [npm CLI `audit signatures` implementation](https://github.com/npm/cli/blob/latest/lib/commands/audit.js)
- [pacote registry attestation verification](https://github.com/npm/pacote/blob/latest/lib/registry.js)
- [SLSA provenance v1](https://slsa.dev/spec/v1.0/provenance)
- [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)

ReleaseGuard's compatibility tests use fixture shapes derived from these interfaces. They do not substitute for npm's cryptographic verification of a live registry artifact.
