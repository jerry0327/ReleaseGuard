# SARIF integration

ReleaseGuard writes `releaseguard.sarif` using SARIF 2.1.0. The report can be retained as a workflow artifact or uploaded to GitHub code scanning.

## Contents

Each finding includes:

- the stable ReleaseGuard rule ID;
- SARIF level derived from ReleaseGuard severity;
- full evidence and remediation text;
- a source path when the finding is path-specific;
- a deterministic partial fingerprint; and
- security and supply-chain tags.

Severity mapping:

| ReleaseGuard | SARIF level | Security severity |
|---|---|---:|
| Low | `note` | 2.0 |
| Medium | `warning` | 5.0 |
| High | `error` | 8.0 |
| Critical | `error` | 9.8 |

The ReleaseGuard decision remains authoritative. SARIF levels are presentation metadata and do not change `fail_on` behavior.

## Artifact-only use

Artifact retention needs no `security-events` permission:

```yaml
- uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7
  if: always()
  with:
    name: releaseguard-evidence
    path: |
      releaseguard-report.json
      releaseguard.sarif
```

## Upload to GitHub code scanning

Code-scanning upload is opt-in. The workflow needs `security-events: write` in addition to read access:

```yaml
permissions:
  contents: read
  pull-requests: read
  security-events: write

steps:
  - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6
    with:
      fetch-depth: 0

  - uses: jerry0327/ReleaseGuard@main
    with:
      github-token: ${{ github.token }}

  - name: Upload ReleaseGuard SARIF
    if: always()
    uses: github/codeql-action/upload-sarif@5595ccaf912efad79be6eef63a5619ff05969be3 # v4
    with:
      sarif_file: releaseguard.sarif
      category: releaseguard
```

Code-scanning availability and token behavior differ between public repositories, private repositories, GitHub Enterprise Cloud, GitHub Enterprise Server, and pull requests from forks. Keep artifact upload enabled even when SARIF upload is unavailable so the policy evidence is not lost.

## Fingerprints

ReleaseGuard fingerprints are derived from rule ID, path, title, and evidence detail. This is intended to keep the same finding stable across repeated scans while allowing materially different evidence to produce a new identity.

Fingerprint compatibility is versioned independently as `releaseguard/v1` inside `partialFingerprints`.
