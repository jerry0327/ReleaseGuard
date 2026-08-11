# ReleaseGuard

[![CI](https://github.com/jerry0327/ReleaseGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/jerry0327/ReleaseGuard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**A deterministic security gate for source changes, release authorization, and published package provenance.**

ReleaseGuard evaluates a release at two different trust boundaries:

1. **Before merge or publication** — inspect the Git delta for install-time execution, dependency redirection, release-workflow mutations, opaque binaries, executable-bit changes, and other high-leverage supply-chain signals.
2. **After npm publication** — ask the npm CLI to cryptographically verify the package's Sigstore attestations, then compare the signed SLSA claims with the expected GitHub repository, workflow, commit, ref, and builder.

> **Status:** early alpha (`0.3.0`). The repository scanner, independent-review gate, npm provenance verifier, JSON evidence, SARIF output, and composite Actions are usable. Pin ReleaseGuard and all third-party Actions to reviewed commit SHAs in production.

ReleaseGuard does not use an LLM as the enforcement root of trust.

## Why ReleaseGuard exists

A compromised maintainer identity can make malicious release activity look routine:

- add an npm `postinstall` hook;
- redirect a dependency to a Git or URL source;
- alter a publish workflow or ownership rule;
- conceal content in a checked-in binary;
- approve a high-risk PR using the same compromised identity; or
- publish a package version from a different repository, workflow, or commit than the release record expects.

ReleaseGuard turns those mutations and identity mismatches into stable, reviewable policy findings.

## Capabilities

### Repository release gate

The root Action and `releaseguard scan` command evaluate repository changes.

| Rule | Signal | Default severity |
|---|---|---:|
| `RG001` | CI, ownership, action, or release-control file changed | High |
| `RG002` | Unexpected binary content changed | High |
| `RG003` | Executable bit introduced | High |
| `RG004` | `preinstall`, `install`, or `postinstall` changed | **Critical** |
| `RG005` | npm release lifecycle hook changed | High |
| `RG006` | Dependency changed to Git/URL/file source | **Critical** |
| `RG007` | New direct dependency introduced | Medium/High |
| `RG008` | Non-conventional package version | Low |
| `RG009` | Version bumped without changelog update | Medium |
| `RG010` | Manifest changed without lockfile update | Low |
| `RG011` | Release delta exceeds configured size | Medium |
| `RG012` | Required independent-review quorum not met | **Critical** |
| `RG013` | Required review evidence unavailable | Critical/High |
| `RG014` | Review evidence is bound to another commit range | **Critical** |

### Published npm provenance gate

The `actions/verify-npm` Action and `releaseguard verify-npm` command evaluate an exact registry artifact.

| Rule | Signal | Default severity |
|---|---|---:|
| `RG015` | Package version has no advertised npm provenance | High |
| `RG016` | npm rejected the target signature or attestation | **Critical** |
| `RG017` | Required cryptographic verifier is unavailable | **Critical** |
| `RG018` | Expected GitHub trusted-publisher marker is missing | High |
| `RG019` | Verified provenance names another repository | **Critical** |
| `RG020` | Verified provenance names another workflow | **Critical** |
| `RG021` | Verified provenance names another source commit | **Critical** |
| `RG022` | Verified provenance names another branch or tag ref | High |
| `RG023` | Verified provenance names another builder | **Critical** |
| `RG024` | Verified attestation structure is malformed or unsupported | **Critical** |
| `RG025` | Registry publish/release attestation is missing | High |

See [Rules and rationale](docs/rules.md) for exact semantics.

## Pull-request gate quick start

```yaml
name: release-guard

on:
  pull_request:

permissions:
  contents: read
  pull-requests: read

jobs:
  releaseguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6
        with:
          fetch-depth: 0

      # Alpha usage. Pin ReleaseGuard to a reviewed commit SHA in production.
      - uses: jerry0327/ReleaseGuard@main
        with:
          config: releaseguard.toml
          github-token: ${{ github.token }}

      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7
        if: always()
        with:
          name: releaseguard-evidence
          path: |
            releaseguard-report.json
            releaseguard.sarif
```

Independent review is opt-in:

```toml
[releaseguard.review]
minimum_independent_approvals = 1
required_on = "high"
allow_stale_approvals = false
exclude_bots = true
fail_closed = true
allowed_author_associations = ["OWNER", "MEMBER", "COLLABORATOR"]
trusted_reviewers = []
```

Read [Independent review evidence](docs/review-evidence.md) before enabling a blocking quorum.

## npm post-publish gate quick start

Run this after `npm publish` in the same trusted-publishing workflow:

```yaml
- uses: jerry0327/ReleaseGuard/actions/verify-npm@main
  with:
    package: ${{ steps.package.outputs.name }}
    version: ${{ steps.package.outputs.version }}
    repository: ${{ github.repository }}
    workflow: .github/workflows/publish.yml
    commit: ${{ github.sha }}
    ref: ${{ github.ref }}
```

The npm Action:

- provisions pinned Node.js `24.18.1` and npm `11.19.0`;
- retries while new registry metadata propagates;
- installs the exact package in a temporary sandbox with lifecycle scripts and bin links disabled;
- uses an allowlisted verifier environment that excludes inherited GitHub, npm, Node, cloud, and other credentials;
- runs `npm audit signatures --json --include-attestations`;
- accepts claims only from the target package's cryptographically verified bundles;
- supports SLSA provenance v1 and legacy v0.2 claim layouts;
- compares repository, workflow, commit, optional ref, and builder identity; and
- emits a compact report without retaining raw Sigstore bundles or review discussion content.

A complete publish example is in [`examples/npm-post-publish.yml`](examples/npm-post-publish.yml).

### Action inputs that matter most

| Input | Default | Meaning |
|---|---|---|
| `package` | required | Exact package name |
| `version` | required | Exact SemVer version; tags and ranges are rejected |
| `repository` | current repository | Expected GitHub `owner/name` |
| `workflow` | current workflow path | Expected `.github/workflows/*.yml` |
| `commit` | `github.sha` | Expected full source SHA |
| `ref` | `github.ref` | Expected branch or tag ref |
| `builder-id` | GitHub-hosted runner | Expected SLSA builder |
| `fail-on` | `high` | Blocking severity |
| `attempts` | `6` | Registry propagation attempts |
| `npm-version` | `11.19.0` | Exact verifier version |

The default policy requires the npm GitHub trusted-publisher marker. Set `allow-token-published-provenance: true` only when a deliberate migration period still permits token-published provenance.

## CLI

ReleaseGuard has no third-party Python runtime dependency and requires Python 3.11+.

```bash
python -m pip install -e .
releaseguard scan --base origin/main --head HEAD
```

Verify a published npm version:

```bash
releaseguard verify-npm @scope/package \
  --version 1.2.3 \
  --repository owner/repository \
  --workflow .github/workflows/publish.yml \
  --commit 0123456789abcdef0123456789abcdef01234567 \
  --ref refs/tags/v1.2.3
```

`verify-npm` requires npm `11.12.0` or newer because it consumes the full verified Sigstore bundles returned by `--include-attestations`. The bundled Action pins npm `11.19.0`.

Exit codes:

- `0`: policy passed;
- `2`: policy completed and blocked release promotion;
- `3`: command input or ReleaseGuard execution failed before a policy report could be completed.

Registry/network/verifier failures that occur inside npm verification are normally represented by critical `RG017` evidence and exit code `2`, not silently ignored.

## Evidence formats

### Repository scan

- `releaseguard-report.json` — schema version 2
- `releaseguard.sarif` — SARIF 2.1.0
- JSON Schema: [`schemas/releaseguard-report.schema.json`](schemas/releaseguard-report.schema.json)

### npm provenance verification

- `releaseguard-npm-report.json` — npm provenance schema version 1
- `releaseguard-npm.sarif` — SARIF 2.1.0 with package PURL locations
- JSON Schema: [`schemas/npm-provenance-report.schema.json`](schemas/npm-provenance-report.schema.json)

The npm report records normalized claims and verification status, not raw DSSE envelopes, certificates, transparency-log entries, auth tokens, or package contents.

A project can optionally attest the ReleaseGuard report itself with GitHub's first-party artifact attestation Action; see [`examples/npm-post-publish-with-attested-evidence.yml`](examples/npm-post-publish-with-attested-evidence.yml).

## Security boundary

ReleaseGuard verifies repository evidence and selected registry evidence, but it is not the package registry, GitHub, Sigstore, or the CI runner.

For npm packages, ReleaseGuard delegates cryptographic signature, certificate-chain, transparency-log, and artifact-subject verification to the official npm CLI. It then applies deterministic identity policy to the statements returned as verified. It does **not** claim that merely decoding `dist.attestations` proves provenance.

ReleaseGuard cannot prevent:

- compromise of npm, GitHub, Sigstore, the runner image, or the operating system;
- an administrator disabling every required workflow or repository rule;
- collusion or compromise of every trusted reviewer;
- malicious source code that violates no configured release invariant;
- publication to an unmonitored package name or registry; or
- proof that every arbitrary binary was reproducibly built from reviewed source.

Read [npm provenance verification](docs/npm-provenance.md) and the full [Threat model](docs/threat-model.md).

## Design principles

- **Deterministic enforcement.** An external model is never required for PASS/BLOCK.
- **Separate pre-release and post-publish boundaries.** Git review evidence and registry artifact evidence are not conflated.
- **Delegate cryptography to maintained ecosystem tooling.** ReleaseGuard does not implement a partial Sigstore verifier in Python.
- **Bind authorization and provenance to exact commits.** Stale or mismatched identities are rejected.
- **Keep evidence narrow.** Reports retain normalized claims rather than secrets or large raw bundles.
- **Fail closed when verification is required.** Missing or unavailable evidence cannot become an accidental pass.
- **Secure the security tooling.** Project workflows pin third-party Actions and Dependabot monitors updates.

See [Architecture](docs/architecture.md), [Adoption guide](docs/adoption-guide.md), and [Roadmap](ROADMAP.md).

## Contributing and security reports

Issues and focused pull requests are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md). Security-sensitive reports must follow [SECURITY.md](SECURITY.md), not a public issue.

## License

MIT — see [LICENSE](LICENSE).
