# ReleaseGuard

**A deterministic security gate for software releases.**

ReleaseGuard inspects the *release delta* before code is published and flags changes that are disproportionately useful to a supply-chain attacker: install-time scripts, non-registry dependencies, release workflow changes, unexpected binaries, new executable files, and other release-control mutations.

> **Status:** early alpha (`0.1.0`). The policy engine and GitHub Action are usable today; registry provenance and identity-aware release controls are on the roadmap.

## Why ReleaseGuard exists

A compromised maintainer account can make malicious code look operationally normal: open or merge a PR, alter a release workflow, add a lifecycle hook, change a dependency source, or publish a new version. Traditional code review can miss these high-leverage changes when they are buried in a large release delta.

ReleaseGuard turns those release invariants into an explicit, reviewable policy gate.

It is designed to answer a narrow question:

> **Did this release change anything that materially increases the ability to execute, redirect, or conceal code at install or publish time?**

## What v0.1 checks

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

By default, only **critical** findings block. Teams can make the gate stricter with `fail_on = "high"` or `"medium"`.

## GitHub Action quick start

ReleaseGuard needs the full Git history so it can compare the pull request base and head commits.

```yaml
name: release-guard

on:
  pull_request:

permissions:
  contents: read

jobs:
  releaseguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      # Alpha usage. For production, pin third-party actions to a reviewed commit SHA.
      - uses: jerry0327/ReleaseGuard@main
        with:
          config: releaseguard.toml
```

The action writes:

- a Markdown summary into the GitHub Actions job summary;
- `decision` (`PASS` or `BLOCK`);
- `risk-score` (`0`–`100`);
- `findings` (count); and
- a machine-readable `releaseguard-report.json` evidence file.

## CLI

ReleaseGuard is dependency-free at runtime on Python 3.11+.

```bash
python -m pip install -e .
releaseguard scan --base origin/main --head HEAD
```

Or run directly from the repository:

```bash
python -m releaseguard scan --base <base-sha> --head <head-sha>
```

Exit codes:

- `0`: policy passed;
- `2`: policy blocked the release;
- `3`: ReleaseGuard could not complete the scan.

## Policy configuration

Create `releaseguard.toml`:

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
```

See [Policy reference](docs/policy-reference.md) for all options.

## Threat model

ReleaseGuard is aimed at malicious or compromised release changes that still travel through a Git/GGitHub-based release process. It is useful when an attacker can author or merge code but the project still has an independent CI gate that must pass before publication.

ReleaseGuard **cannot** stop an attacker who can bypass GitHub entirely and publish directly with an unrestricted registry credential. Closing that gap requires registry-side controls such as trusted publishing/OIDC, provenance, protected environments, independent approvals, and short-lived credentials. Those controls are part of the integration roadmap, not claims of the current version.

Read the full [threat model](docs/threat-model.md).

## Design principles

- **Deterministic first.** A release can be blocked without sending source code to an external service.
- **Explain every finding.** Each rule has an ID, severity, evidence path, and remediation.
- **Review the delta, not just the final tree.** Supply-chain attacks often hide in small but high-leverage mutations.
- **Evidence is an artifact.** The JSON report can be retained with release records or fed into later attestation work.
- **Secure the security tooling.** ReleaseGuard treats its own workflows and action definition as protected release-control files.

## Current scope and roadmap

The first release focuses on GitHub and npm-oriented release risk signals while keeping generic binary, executable, workflow, and manifest controls.

Next planned work includes:

1. GitHub review quorum and actor/release-context evidence.
2. npm trusted-publishing and provenance verification.
3. Signed release evidence / attestations.
4. First-class PyPI and Cargo manifest rules.
5. Optional AI-assisted explanation for ambiguous multi-file release changes, without making an LLM the enforcement root of trust.

See [ROADMAP.md](ROADMAP.md).

## Contributing

Issues and pull requests are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md). Security-sensitive reports should follow [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).
