# SARIF integration

ReleaseGuard writes SARIF 2.1.0 for both repository scans and npm provenance verification. SARIF is an interoperable presentation of findings; the JSON evidence report and ReleaseGuard exit code remain authoritative.

## Repository scan SARIF

Default path: `releaseguard.sarif`

- source-file locations where applicable;
- rule IDs `RG001`–`RG014`;
- `releaseguard/v1` partial fingerprints; and
- scan base/head and decision metadata.

## npm provenance SARIF

Default path: `releaseguard-npm.sarif`

- package URL locations, for example `pkg:npm/%40scope/name@1.2.3`;
- rule IDs `RG015`–`RG025`;
- `releaseguard/npm-v1` partial fingerprints bound to package/version; and
- expected/observed release identity metadata.

## Severity mapping

| ReleaseGuard | SARIF level | Security severity |
|---|---|---:|
| Low | `note` | 2.0 |
| Medium | `warning` | 5.0 |
| High | `error` | 8.0 |
| Critical | `error` | 9.8 |

SARIF `error` does not independently determine whether ReleaseGuard exits `2`; `fail_on` remains the policy threshold.

## Artifact-only retention

```yaml
- uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7
  if: always()
  with:
    name: releaseguard-evidence
    path: |
      releaseguard-report.json
      releaseguard.sarif
      releaseguard-npm-report.json
      releaseguard-npm.sarif
    if-no-files-found: ignore
```

Artifact retention needs no `security-events` permission.

## Upload to GitHub code scanning

Code-scanning upload is opt-in and requires `security-events: write` where supported:

```yaml
permissions:
  contents: read
  pull-requests: read
  security-events: write

steps:
  - name: Upload ReleaseGuard repository SARIF
    if: always()
    uses: github/codeql-action/upload-sarif@5595ccaf912efad79be6eef63a5619ff05969be3 # v4
    with:
      sarif_file: releaseguard.sarif
      category: releaseguard-repository

  - name: Upload ReleaseGuard npm SARIF
    if: always()
    uses: github/codeql-action/upload-sarif@5595ccaf912efad79be6eef63a5619ff05969be3 # v4
    with:
      sarif_file: releaseguard-npm.sarif
      category: releaseguard-npm
```

Code-scanning availability and token behavior differ by repository type and fork context. Keep artifact retention enabled even when code-scanning upload is unavailable.

## Fingerprint compatibility

Repository fingerprints preserve the original v0.2 input material under `releaseguard/v1`. npm fingerprints use a separate namespace and include exact package/version context.

An intentional fingerprint identity change requires a new namespace and changelog entry.
