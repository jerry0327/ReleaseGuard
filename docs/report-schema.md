# JSON evidence schema

ReleaseGuard v0.2 writes report schema version `2`.

The canonical machine-readable schema is [`schemas/releaseguard-report.schema.json`](../schemas/releaseguard-report.schema.json).

## Compatibility policy before 1.0

- `schema_version` changes when a consumer-breaking report shape is introduced.
- New optional fields can be added without changing the schema version.
- Stable rule IDs are retained unless a rule's security meaning is replaced rather than refined.
- Consumers should ignore unknown object properties and unknown rule IDs.

## Top-level fields

- `schema_version`
- `tool.name` and `tool.version`
- `base` and `head` full commit SHAs
- `decision`
- `risk_score`
- `fail_on`
- `changed_files`
- `findings[]`
- `review_evidence` when evaluated

## Review-evidence status

- `not_required` — review policy disabled or no deterministic finding reached the trigger.
- `passed` — enough approvals counted.
- `failed` — evidence was available, but quorum was not met.
- `unavailable` — required evidence could not be obtained or parsed.
- `mismatch` — scanned commit range did not match pull-request context.
