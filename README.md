# ReleaseGuard

**A deterministic security gate for software releases.**

ReleaseGuard inspects the *release delta* before publication and turns high-leverage supply-chain changes into explicit policy evidence. It detects install-time execution, dependency redirection, release-workflow mutations, opaque binaries, executable-bit changes, and other release-control risks. When enabled, it also verifies that high-risk changes have fresh, independent approvals bound to the exact pull-request commit.

> **Status:** early alpha (`0.2.0`). The local policy engine, GitHub Action, review-evidence gate, JSON report, and SARIF output are usable. Registry provenance verification remains roadmap work.

## Why ReleaseGuard exists

A compromised maintainer account can make a malicious release look operationally normal: alter a publish workflow, add a lifecycle hook, redirect a dependency, conceal code in a binary, or merge a release PR using only the compromised identity.

Traditional review often treats those mutations as ordinary files inside a large diff. ReleaseGuard instead asks two narrower questions:

1. **Did this release gain new execution, dependency redirection, opacity, or release-control capability?**
2. **When policy requires it, did a trusted reviewer other than the author approve this exact head commit?**

ReleaseGuard remains deterministic: no external model is required to pass or block a release.

## What v0.2 checks

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

By default, only **critical** findings block. Independent-review enforcement is initially disabled until a project explicitly sets a non-zero quorum.

See [Rules and rationale](docs/rules.md) for detailed semantics and expected false positives.

## GitHub Action quick start

ReleaseGuard needs full Git history to compare the pull-request base and head commits. `pull-requests: read` is only used when review evidence is enabled.

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
        id: releaseguard
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

The action outputs:

- `decision`: `PASS` or `BLOCK`;
- `risk-score`: `0`–`100`, with severity-preserving score bands;
- `findings`: total finding count;
- `report-path`: JSON evidence path; and
- `sarif-path`: SARIF 2.1.0 path.

## Enable independent-review enforcement

Start with review evidence disabled, then enable it after the workflow has `pull-requests: read` permission and the token is passed to the action.

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

An approval counts only when all applicable conditions are met:

- the reviewer is not the pull-request author;
- the latest decisive review from that reviewer is `APPROVED`;
- the review targets the scanned head commit, unless stale approvals were explicitly allowed;
- the reviewer is not a bot when bot exclusion is enabled; and
- the reviewer has an allowed GitHub author association or is explicitly listed in `trusted_reviewers`.

Comments do not erase an earlier approval, but a later `CHANGES_REQUESTED` or dismissed review does. ReleaseGuard also binds the scanned base/head range to the pull-request context before accepting approvals.

Read [Independent review evidence](docs/review-evidence.md) before enabling a blocking quorum.

## CLI

ReleaseGuard has no third-party runtime dependency on Python 3.11+.

```bash
python -m pip install -e .
releaseguard scan --base origin/main --head HEAD
```

For a GitHub pull-request scan with review evidence, keep the token in an environment variable rather than a command-line argument:

```bash
export RELEASEGUARD_GITHUB_TOKEN="..."
releaseguard scan \
  --base <base-sha> \
  --head <head-sha> \
  --repository owner/repository \
  --pull-request 123
```

Exit codes:

- `0`: policy passed;
- `2`: policy completed and blocked the release;
- `3`: ReleaseGuard could not complete the scan.

## Policy configuration

A minimal `releaseguard.toml`:

```toml
[releaseguard]
fail_on = "critical"
max_changed_files = 200
changelog_paths = ["CHANGELOG.md"]
protected_patterns = [
  ".github/workflows/**",
  ".github/CODEOWNERS",
  "CODEOWNERS",
  ".npmrc",
  "action.yml",
  "scripts/release/**",
]
allowed_binary_patterns = ["docs/**", "assets/**"]

[releaseguard.review]
minimum_independent_approvals = 0
required_on = "high"
```

See the complete [Policy reference](docs/policy-reference.md) and the staged [Adoption guide](docs/adoption-guide.md).

## Evidence formats

### JSON

`releaseguard-report.json` is the durable policy record. Schema version 2 includes:

- tool version and scanned commit range;
- decision, score, threshold, and changed-file count;
- stable rule IDs, severity, path, evidence, and remediation; and
- review-evidence status, counted approvals, excluded approvals, and commit binding.

A JSON Schema is provided at [`schemas/releaseguard-report.schema.json`](schemas/releaseguard-report.schema.json).

### SARIF

`releaseguard.sarif` uses SARIF 2.1.0 with stable fingerprints so results can be retained as an artifact or uploaded to GitHub code scanning. Upload is opt-in because it requires `security-events: write` and availability differs by repository type.

See [SARIF integration](docs/sarif.md).

## Security boundary

ReleaseGuard is aimed at malicious or compromised changes that still travel through a Git/GitHub-based release process. It is useful when an attacker can author or merge code but at least one independent CI, review, or protected-release control remains enforceable.

ReleaseGuard **cannot** stop an attacker who can bypass GitHub and publish directly with an unrestricted registry credential. It also does not prove that an arbitrary binary was reproducibly built from reviewed source. Closing those gaps requires trusted publishing/OIDC, provenance and attestations, protected environments, short-lived credentials, and reproducible builds.

Read the full [Threat model](docs/threat-model.md).

## Architecture and design principles

- **Deterministic first.** No external model or hosted ReleaseGuard service is required.
- **Bind evidence to commits.** Review evidence is rejected when it describes a different range.
- **Do not trust public approval by default.** Reviewer association or explicit trust is required.
- **Explain every finding.** Stable IDs, paths, details, and remediation are preserved.
- **Evidence is an artifact.** JSON and SARIF can be retained with release records.
- **Secure the security tooling.** ReleaseGuard's own Actions are pinned to full commit SHAs and monitored by Dependabot.

See [Architecture](docs/architecture.md).

## Roadmap

The next major work is registry identity and provenance:

1. npm trusted-publishing / OIDC verification;
2. published provenance validation against repository, workflow, and commit;
3. signed ReleaseGuard evidence envelopes;
4. first-class PyPI and Cargo dependency rules; and
5. policy baselines and time-bounded exceptions for mature repositories.

See [ROADMAP.md](ROADMAP.md).

## Contributing and security reports

Issues and pull requests are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md). Security-sensitive reports must follow [SECURITY.md](SECURITY.md) rather than a public issue.

## License

MIT — see [LICENSE](LICENSE).
