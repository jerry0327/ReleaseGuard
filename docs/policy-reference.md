# Policy reference

ReleaseGuard reads `releaseguard.toml` from the repository working directory by default. Missing configuration uses conservative built-in defaults.

## `[releaseguard]`

### `fail_on`

One of `low`, `medium`, `high`, or `critical`. Findings at or above the selected severity make the scan exit with code `2`.

Default: `critical`.

A new project should generally start at `critical`, inspect real findings, then move toward `high` after intentional exceptions are represented in policy.

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

Array of recognized lockfiles. The v0.1 consistency rule is intentionally generic; ecosystem-specific lockfile verification is planned.

### `protected_patterns`

Glob patterns for files that can materially change release behavior, ownership, or CI execution. A match produces `RG001` (`high`).

Default patterns include GitHub Actions workflows, CODEOWNERS, `.npmrc`, `action.yml`, and `scripts/release/**`.

### `allowed_binary_patterns`

Glob patterns where binary changes do not produce `RG002`.

Defaults: `docs/**` and `assets/**`.

Allowlisting a path does not verify the binary; it only suppresses that specific finding.

## Severity semantics

- **Critical** — direct path to automatic code execution or dependency-source redirection at install/publish time.
- **High** — changes release controls, opaque artifacts, executability, or production dependency surface.
- **Medium** — review-quality or release-consistency signal that materially raises scrutiny.
- **Low** — hygiene or consistency signal with significant legitimate variation across projects.
