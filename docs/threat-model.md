# Threat model

## Security goals

ReleaseGuard applies three related invariants:

> A release should not silently gain execution, dependency redirection, artifact opacity, build-time code, or release-control capability without explicit evidence.

> When policy requires independent review, the author should not satisfy that boundary using self-approval, stale approval, bot approval, untrusted public approval, or approval for another commit range.

> A published npm package should not be promoted when cryptographically verified provenance identifies a different repository, workflow, commit, ref, or builder than expected.

## Primary attacker behaviors

- Add npm lifecycle execution.
- Redirect npm, Python, or Cargo dependencies to attacker-controlled Git, URL, path, registry, patch, or replacement sources.
- Introduce or alter Python build backends, Cargo build scripts, or native-link metadata.
- Hide content in binaries or large changes.
- Alter workflows, ownership, Action metadata, or publish configuration.
- Reuse stale or self-issued review evidence.
- Publish the expected npm version from another source identity.
- Supply malformed manifests or evidence that cause a security tool to skip analysis.

## Defender assumptions

At least one independent enforcement point remains effective: a required check, protected branch/environment, trusted reviewer, protected trusted-publisher configuration, or post-publish promotion gate.

For npm verification, the defender trusts the selected npm binary, Node.js runtime, npm registry, Sigstore trust infrastructure, GitHub Actions claims, TLS/network path, and runner operating system.

## Controls

- Exact Git range and package-version inputs.
- Stable deterministic findings and fail-closed supported parsers.
- Independent review filtering and commit binding.
- Credential-isolated npm subprocesses with scripts and bin links disabled.
- Delegated npm cryptographic verification followed by expected-identity policy.
- Bounded output, payload, retry, timeout, and attestation processing.
- Versioned JSON schemas, SARIF fingerprints, and release-readiness checks.

## Out of scope

ReleaseGuard alone does not prevent:

- compromise of GitHub, npm, PyPI, crates.io, Sigstore, TLS, a runner, or operating system;
- a repository administrator disabling every required control;
- compromise or collusion of all trusted reviewers;
- malicious source code that violates no configured invariant;
- publication to an unmonitored package or registry;
- proof that arbitrary binaries are reproducibly built;
- authenticated private-registry verification;
- native PyPI attestation verification in `0.4.0`; or
- source-code correctness or vulnerability discovery in general.

## Private data

Reports exclude secrets, private review bodies, raw package contents, raw DSSE bundles, certificates, and transparency-log records. Repository scans are local; optional GitHub and npm network boundaries are documented separately.

## Defense in depth

Use ReleaseGuard with protected branches/tags/environments, CODEOWNERS, short-lived trusted-publishing credentials, registry account recovery controls, pinned Actions, retained evidence, isolated builds, and reproducible-build verification where practical.
