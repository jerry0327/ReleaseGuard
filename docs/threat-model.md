# Threat model

## Security goals

ReleaseGuard applies three related invariants:

> A release should not silently gain new execution, dependency redirection, artifact opacity, or release-control capability without explicit evidence.

> When policy requires independent review, the author should not satisfy that boundary using self-approval, stale approval, bot approval, untrusted public approval, or approval for another commit range.

> A published npm package should not be promoted when its cryptographically verified provenance identifies a different repository, workflow, commit, ref, or builder than the release record expects.

## Primary attackers

### Compromised repository identity

An attacker controls a maintainer account or credential that can influence repository contents. They may alter package metadata, lifecycle scripts, dependencies, workflows, ownership, binaries, or review state.

### Release-path substitution

An attacker publishes the expected package/version from another source repository, workflow, commit, ref, or builder, or uses a reusable registry token when policy expects trusted publishing.

### Evidence confusion

An attacker attempts to make metadata presence, stale approvals, another package's verified record, an unsupported statement, or a different commit's evidence appear sufficient.

## Defender assumptions

At least one independent enforcement point remains effective, such as:

- a required ReleaseGuard check;
- protected branch or environment;
- independent reviewer;
- protected trusted-publishing configuration; or
- post-publish promotion gate.

For npm verification, the defender trusts the selected npm binary, Node.js runtime, npm registry, Sigstore trust infrastructure, GitHub Actions identity claims, TLS/network path, and runner operating system.

## Controls

### Repository delta

ReleaseGuard surfaces install-time execution, dependency redirection, release-control mutations, opaque binary changes, new executability, and unusually large deltas.

### Review authorization

ReleaseGuard filters approvals by author independence, latest decisive state, commit freshness, bot status, repository trust relationship, and exact PR range.

### Published npm provenance

ReleaseGuard:

- requires an exact package and version;
- isolates npm from credentials and lifecycle execution;
- delegates cryptographic validation to npm;
- filters npm output to the target package;
- supports explicit SLSA layouts only;
- rejects conflicting/unsupported structures;
- compares source and builder identity; and
- distinguishes absent, invalid, unavailable, and mismatched evidence.

## Out of scope for v0.3

ReleaseGuard alone does not prevent:

- compromise of npm, GitHub, Sigstore, TUF, transparency logs, TLS, the runner, or operating system;
- a repository/organization administrator disabling every required control;
- compromise or collusion of all trusted reviewers;
- malicious source code that violates no configured invariant;
- publication to another package name or registry that no gate monitors;
- package takeover or account-recovery failures outside the observed release;
- proof that arbitrary binaries are reproducibly built from reviewed source;
- authenticated private-registry verification;
- native verification of PyPI attestations or Cargo release provenance; or
- native signing and verification of ReleaseGuard's own report envelope.

These are not treated as solved.

## Bootstrap and verifier trust

The npm composite Action pins its setup Action, Node.js version, and npm version. However, bootstrap still depends on GitHub Actions infrastructure and downloading npm from the public registry. Exact version pinning improves reproducibility but is not a self-verifying bootstrap chain.

A compromised npm binary can forge its own `verified` output. ReleaseGuard therefore records the npm version and treats npm as part of the trust base rather than claiming independent cryptographic verification.

## Private data and credentials

The npm verifier is designed for public/anonymous artifacts. It deliberately strips credentials instead of accepting private registry tokens. Reports exclude raw DSSE bundles, certificates, transparency-log entries, package files, npm configuration, environment secrets, and review bodies.

## Defense in depth

A strong deployment combines ReleaseGuard with:

- protected branches and release environments;
- required checks and CODEOWNERS review;
- npm trusted publishing with short-lived OIDC credentials;
- restricted package ownership/recovery controls;
- pinned Actions and reviewed updates;
- retained JSON/SARIF evidence;
- artifact/report attestations where useful;
- isolated release builds; and
- reproducible-build verification where practical.
