# Policy reference

ReleaseGuard reads `releaseguard.toml` from the repository working directory by default. A missing configuration file uses built-in defaults.

## `[releaseguard]`

### `fail_on`

One of `low`, `medium`, `high`, or `critical`. Findings at or above the selected severity make the scan exit with code `2`.

Default: `critical`.

### `max_changed_files`

Positive integer. A release delta larger than this produces `RG011` (`medium`).

Default: `200`.

### `changelog_paths`

Array of paths that count as release notes for `RG009`.

Default: `['CHANGELOG.md']`.

### `manifest_paths`

Array of dependency/package manifest paths used for manifest/lockfile consistency checks.

Defaults:

- `package.json`
- `pyproject.toml`
- `Cargo.toml`

### `lockfile_paths`

Array of recognized lockfiles. The v0.2 consistency rule is intentionally generic; package-manager-specific verification is planned.

### `protected_patterns`

Glob patterns for files that can materially change release behavior, ownership, or CI execution. A match produces `RG001` (`high`).

Default patterns include GitHub Actions workflows, CODEOWNERS, `.npmrc`, `action.yml`, and `scripts/release/**`.

### `allowed_binary_patterns`

Glob patterns where binary changes do not produce `RG002`.

Defaults: `docs/**` and `assets/**`.

Allowlisting a path does not verify the binary. It only suppresses that rule for matching paths.

## `[releaseguard.review]`

### `minimum_independent_approvals`

Integer from `0` to `20`. Zero disables review-evidence enforcement. A positive value requires that many counted approvals when a deterministic finding reaches `required_on`.

Default: `0`.

### `required_on`

One of `low`, `medium`, `high`, or `critical`. This is the severity that triggers review-evidence evaluation.

Default: `high`.

### `allow_stale_approvals`

Boolean. When false, an approval counts only if its `commit_id` matches the scanned head SHA.

Default: `false`.

Setting this to true weakens commit binding and should be exceptional.

### `exclude_bots`

Boolean. Excludes accounts whose GitHub user type is `Bot` or whose login ends in `[bot]`.

Default: `true`.

### `fail_closed`

Boolean. When true, unavailable required review evidence produces critical `RG013`. When false, it produces high severity.

Default: `true`.

This does not weaken `RG012` or `RG014`; an explicitly unmet quorum or range mismatch remains critical.

### `allowed_author_associations`

Array of GitHub author-association values accepted as trusted reviewer context.

Default:

```toml
["OWNER", "MEMBER", "COLLABORATOR"]
```

Other recognized values may be configured, but including `NONE` makes arbitrary public approvals eligible and is not recommended.

### `trusted_reviewers`

Array of GitHub logins allowed to count even when their author association is not in `allowed_author_associations`.

Default: `[]`.

Use this for named external auditors, not as a substitute for maintaining collaborator access correctly.

## Severity semantics

- **Critical** — direct install/publish execution, dependency-source redirection, or failure of an explicitly configured review boundary.
- **High** — release-control, opaque artifact, executability, production dependency, or fail-open evidence risk.
- **Medium** — review-quality or release-consistency signal that materially raises scrutiny.
- **Low** — hygiene or consistency signal with substantial legitimate variation.
