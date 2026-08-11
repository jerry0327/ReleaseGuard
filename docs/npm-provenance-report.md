# npm provenance JSON report

`releaseguard verify-npm` writes `releaseguard-npm-report.json` using npm provenance schema version `1`.

The canonical JSON Schema is [`schemas/npm-provenance-report.schema.json`](../schemas/npm-provenance-report.schema.json).

## Compatibility policy before 1.0

- `schema_version` changes for a consumer-breaking shape change.
- Additive optional fields do not require a schema increment.
- Consumers should ignore unknown properties and unknown rule IDs.
- Normalized identity fields are evidence summaries, not raw Sigstore bundles.
- SARIF fingerprints are independently versioned as `releaseguard/npm-v1`.

## Top-level fields

- `schema_version`: currently `1`
- `report_type`: `npm-provenance`
- `tool.name` and `tool.version`
- `package.name`, `package.version`, and `package.registry`
- `expected_identity`
- `decision`
- `risk_score`
- `fail_on`
- `findings[]`
- `evidence`

## `expected_identity`

The policy boundary selected by the caller:

- `repository`
- `workflow`
- `commit_sha`
- optional `ref`
- `builder_id`
- `require_trusted_publisher`

## `evidence.status`

- `verified` — npm cryptographically accepted the target package's evidence; identity findings may still block.
- `missing` — registry metadata did not advertise provenance.
- `invalid` — npm rejected evidence or the verified statement could not be safely interpreted.
- `unavailable` — a supported verifier, registry response, network path, or command result was unavailable.

`verified` does not imply `PASS`: repository, workflow, commit, ref, builder, trusted-publisher, or publication-attestation policy can still fail.

## Evidence fields

The report can include:

- verifier command and npm version;
- attempt count;
- registry integrity;
- sanitized tarball and attestation URLs;
- trusted-publisher ID and opaque OIDC configuration ID;
- in-toto statement and predicate type;
- verified and publish attestation predicate types;
- signed subject PURL and SHA-512 digest;
- repository, workflow, commit, ref, builder, and invocation identity; and
- a bounded human-readable detail.

URLs are stripped of user information, query strings, and fragments before persistence.

## Deliberately excluded data

The report does not contain:

- DSSE envelope payloads or signatures;
- Fulcio certificates;
- transparency-log entries;
- raw npm audit output;
- registry or GitHub credentials;
- inherited environment variables;
- `.npmrc` contents;
- downloaded package files; or
- review discussion content.

## Decision and exit code

- `PASS` / exit `0`: no finding reached `fail_on`.
- `BLOCK` / exit `2`: verification completed and policy blocked promotion.
- exit `3`: invalid command input or ReleaseGuard failed before a policy report could be completed.

Operational npm/network failures encountered inside the verifier are generally represented as `RG017` and therefore produce a durable `BLOCK` report rather than disappearing as an unclassified command failure.
