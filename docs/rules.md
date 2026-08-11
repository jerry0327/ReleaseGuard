# Rules and rationale

ReleaseGuard rule IDs are intended to remain stable. Severity or wording can evolve before 1.0, but incompatible semantic changes are documented in the changelog.

## Repository-delta rules

### RG001 — Release-control file changed

**Severity:** High

Matches configured `protected_patterns`, including workflows, CODEOWNERS, action metadata, `.npmrc`, and release scripts. These files can redefine who approves a release, what executes in CI, or where a package is published.

**Expected false positives:** routine CI maintenance. The change still deserves independent scrutiny; broad suppression is discouraged.

### RG002 — Unexpected binary content changed

**Severity:** High

Git marks a changed path as binary outside `allowed_binary_patterns`. Binary diffs are materially harder to review and can conceal executable content.

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

A configured manifest changed but no configured lockfile changed. This is generic; ecosystem-specific consistency checks remain roadmap work.

### RG011 — Release delta unusually large

**Severity:** Medium

The number of changed files exceeds `max_changed_files`. Large deltas can hide small high-leverage changes and reduce review quality.

## Review-evidence rules

### RG012 — Independent review quorum not met

**Severity:** Critical

The review gate was triggered, but the number of fresh, independent, trusted approvals was below policy. Evidence includes excluded stale, self, bot, and untrusted approvals plus active changes-requested states.

### RG013 — Required review evidence unavailable

**Severity:** Critical when `fail_closed = true`; otherwise High

The gate required GitHub evidence, but repository/PR context, token permission, API availability, or expected response data was unavailable.

### RG014 — Review evidence bound to another commit range

**Severity:** Critical

The scanned range does not match the pull-request event/API range. Review evidence is rejected instead of being reused across the mismatch.

## Published npm provenance rules

### RG015 — npm provenance missing

**Severity:** High

The exact package version's registry metadata does not advertise an attestation endpoint. No cryptographic provenance evaluation can proceed.

**Expected transient case:** newly published metadata may not have propagated. The npm Action retries by default.

### RG016 — npm attestation verification failed

**Severity:** Critical

The official npm verifier rejected the target package's registry signature, Sigstore attestation, certificate/log evidence, or package subject. A target package that is absent from npm's verified result is also rejected.

### RG017 — npm cryptographic verifier unavailable

**Severity:** Critical

ReleaseGuard could not obtain a supported npm verifier result because npm is missing/too old, the registry/network is unavailable, the command timed out, or expected JSON could not be obtained safely.

This is a policy finding rather than an accidental pass.

### RG018 — npm trusted publisher missing

**Severity:** High

Policy requires GitHub trusted publishing, but registry metadata does not contain both `trustedPublisher.id = "github"` and a non-empty OIDC configuration ID.

Valid provenance can exist without this marker during token-based publication; use the explicit migration option only when that weaker credential model is intentional.

### RG019 — npm provenance repository mismatch

**Severity:** Critical

The cryptographically verified SLSA statement identifies a different GitHub repository, or no supported repository identity.

### RG020 — npm provenance workflow mismatch

**Severity:** Critical

The verified statement identifies another workflow path or omits a supported workflow identity.

### RG021 — npm provenance commit mismatch

**Severity:** Critical

The verified statement identifies another source commit or omits a canonical commit claim.

### RG022 — npm provenance ref mismatch

**Severity:** High

The verified statement identifies another branch/tag ref or omits the ref while the caller constrained one.

### RG023 — npm provenance builder mismatch

**Severity:** Critical

The verified statement names another SLSA builder identity. The default is GitHub's hosted runner builder.

### RG024 — npm attestation metadata malformed or unsupported

**Severity:** Critical

npm cryptographically accepted the bundle, but ReleaseGuard cannot safely interpret its in-toto/SLSA structure. Examples include malformed DSSE JSON, conflicting provenance identities, unsupported statement type, unexpected package subject, or non-canonical SHA-512 subject digest.

This fail-closed behavior prevents a new or ambiguous schema from being silently interpreted as the old one.

### RG025 — npm registry publish/release attestation missing

**Severity:** High

The verified bundle contains build provenance but no recognized npm publish attestation or in-toto release attestation. This reduces evidence that the registry accepted the specific artifact as a publication event.
