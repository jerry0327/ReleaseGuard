# Rules and rationale

ReleaseGuard rule IDs are intended to remain stable. Severity or wording can evolve before 1.0, but incompatible semantic changes will be documented in the changelog.

## Repository-delta rules

### RG001 — Release-control file changed

**Severity:** High

Matches configured `protected_patterns`, including workflows, CODEOWNERS, action metadata, `.npmrc`, and release scripts. These files can redefine who approves a release, what executes in CI, or where a package is published.

**Expected false positives:** routine CI maintenance. The change still deserves independent scrutiny; broad suppression is discouraged.

### RG002 — Unexpected binary content changed

**Severity:** High

Git marks a changed path as binary outside `allowed_binary_patterns`. Binary diffs are materially harder to review and can conceal executable content.

**Expected false positives:** checked-in fixtures, media, or generated assets outside configured asset paths.

### RG003 — Executable bit introduced

**Severity:** High

A changed file gains executable mode. This can turn reviewed inert content into directly executable content.

### RG004 — npm install lifecycle hook changed

**Severity:** Critical

A new or changed `preinstall`, `install`, or `postinstall` script can execute automatically on downstream systems during package installation.

### RG005 — npm release lifecycle hook changed

**Severity:** High

A changed `prepare`, `prepublish`, or `prepublishOnly` hook can alter the package around publish time.

### RG006 — Non-registry dependency source introduced

**Severity:** Critical

A dependency changes to Git, URL, file, link, GitHub, GitLab, or Bitbucket syntax. This bypasses the expected registry version model and can redirect code resolution.

### RG007 — New direct dependency introduced

**Severity:** High for production-facing sections; Medium for `devDependencies`

A new direct dependency expands the release or build trust surface.

### RG008 — Non-conventional package version

**Severity:** Low

The npm version changed to a value outside conventional SemVer syntax. Some projects intentionally use another scheme.

### RG009 — Version changed without changelog update

**Severity:** Medium

The package version changed while no configured changelog path changed.

### RG010 — Manifest changed without lockfile update

**Severity:** Low

A configured manifest changed but no configured lockfile changed. This is generic in v0.2; ecosystem-specific consistency checks are roadmap work.

### RG011 — Release delta unusually large

**Severity:** Medium

The number of changed files exceeds `max_changed_files`. Large deltas can hide small high-leverage changes and reduce review quality.

## Review-evidence rules

### RG012 — Independent review quorum not met

**Severity:** Critical

The review gate was triggered, but the number of fresh, independent, trusted approvals was below policy. The finding includes excluded stale, self, bot, and untrusted approvals plus active changes-requested states.

### RG013 — Required review evidence unavailable

**Severity:** Critical when `fail_closed = true`; otherwise High

The gate required GitHub evidence, but repository/PR context, token permission, API availability, or expected response data was unavailable.

### RG014 — Review evidence bound to another commit range

**Severity:** Critical

The scanned range does not match the pull-request event/API range. Review evidence is rejected instead of being reused across the mismatch.
