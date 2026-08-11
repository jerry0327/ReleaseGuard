# Threat model

## Security goal

ReleaseGuard reduces the chance that a malicious release delta is treated as routine when an attacker has obtained enough repository access to author or merge changes.

The core invariant is:

> A release should not silently gain new execution, dependency redirection, artifact opacity, or release-control capability without producing explicit evidence for review.

## Primary attacker

The v0.1 model assumes an attacker has compromised a maintainer account or another credential that can influence repository contents. The attacker may be able to:

- open or modify a release PR;
- commit source changes;
- alter package metadata;
- add dependencies or lifecycle scripts;
- modify CI or release workflow files; or
- attempt to hide payloads in binary artifacts.

The defender still has at least one independent enforcement point: a CI job, protected environment, review requirement, or release workflow that the attacker cannot simply bypass without producing additional evidence.

## High-leverage changes

ReleaseGuard prioritizes changes that can produce disproportionate supply-chain impact:

1. **Install-time execution** — package lifecycle hooks can run on downstream user machines.
2. **Dependency redirection** — Git, URL, file, or other non-standard dependency sources can replace the code users expect.
3. **Release-pipeline mutation** — workflow, ownership, action, or release script changes can redefine what gets built or published.
4. **Opaque artifacts** — binary changes are materially harder to review than source.
5. **New executability** — mode changes can convert inert content into directly executable content.
6. **Large release deltas** — high-risk mutations are easier to conceal in unusually broad changes.

## Out of scope for v0.1

ReleaseGuard alone does not prevent:

- direct registry publication with a stolen long-lived token;
- compromise of GitHub itself, the package registry, or the CI runner image;
- malicious code that is semantically subtle but does not violate a configured release invariant;
- social engineering of every independent reviewer;
- a project administrator disabling every required control; or
- proof that a binary artifact was reproducibly built from the reviewed source.

These are not treated as solved problems.

## Defense in depth

A strong deployment combines ReleaseGuard with:

- protected default and release branches;
- independent reviews for release-control changes;
- protected deployment environments;
- short-lived OIDC/trusted-publishing credentials instead of reusable publish tokens;
- provenance/attestation verification;
- registry-side MFA and recovery controls; and
- reproducible or isolated release builds where practical.

Future ReleaseGuard versions will verify more of this evidence directly.
