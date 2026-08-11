# JSON evidence schemas

ReleaseGuard writes separate reports for separate trust boundaries.

## Repository scan report

`releaseguard scan` writes repository report schema version `2`.

Canonical schema: [`schemas/releaseguard-report.schema.json`](../schemas/releaseguard-report.schema.json)

Top-level fields include:

- tool version;
- scanned base/head SHAs;
- decision, score, threshold, and changed-file count;
- deterministic findings; and
- optional GitHub review evidence.

Review-evidence status values:

- `not_required`
- `passed`
- `failed`
- `unavailable`
- `mismatch`

## npm provenance report

`releaseguard verify-npm` writes npm provenance schema version `1`.

Canonical schema: [`schemas/npm-provenance-report.schema.json`](../schemas/npm-provenance-report.schema.json)

Top-level fields include:

- exact package/registry identity;
- expected repository/workflow/commit/ref/builder identity;
- decision, score, and threshold;
- npm provenance findings; and
- normalized cryptographic-verifier evidence.

See [npm provenance report](npm-provenance-report.md) for field semantics and deliberately excluded data.

## Compatibility policy before 1.0

- A consumer-breaking shape change increments the relevant `schema_version`.
- Additive optional fields can be introduced without an increment.
- Consumers should ignore unknown properties and unknown rule IDs.
- Rule IDs remain stable unless the security meaning is replaced rather than refined.
- Repository and npm schemas can evolve independently.

## SARIF compatibility

SARIF output is presentation/interoperability evidence and does not replace the JSON report or determine the exit code.

Fingerprint namespaces:

- repository scan: `releaseguard/v1`
- npm provenance: `releaseguard/npm-v1`

An intentional identity break requires a new namespace and changelog entry.
