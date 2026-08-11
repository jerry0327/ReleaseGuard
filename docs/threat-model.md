# Threat model

## Security goal

ReleaseGuard reduces the chance that a malicious release delta is treated as routine when an attacker has obtained enough repository access to author or merge changes.

The v0.2 invariants are:

> A release should not silently gain new execution, dependency redirection, artifact opacity, or release-control capability without explicit evidence.

> When policy requires independent review, the author should not be able to satisfy that control using self-approval, stale approval, bot approval, public drive-by approval, or approval for a different commit range.

## Primary attacker

The model assumes an attacker has compromised a maintainer account or another credential that can influence repository contents. The attacker may be able to:

- open or modify a release PR;
- commit source changes;
- alter package metadata;
- add dependencies or lifecycle scripts;
- modify CI or release workflow files;
- attempt to hide payloads in binary artifacts;
- self-approve using the compromised author identity; or
- attempt to reuse approval obtained before another commit was pushed.

The defender still has at least one enforcement point that the attacker cannot silently bypass: a required CI job, protected branch/environment, independent reviewer, or controlled release workflow.

## High-leverage changes

ReleaseGuard prioritizes:

1. **Install-time execution** — lifecycle hooks can run on downstream systems.
2. **Dependency redirection** — Git, URL, file, or other non-standard sources can replace expected code.
3. **Release-pipeline mutation** — workflow, ownership, action, or release-script changes can redefine what is built or published.
4. **Opaque artifacts** — binary changes are harder to review than source.
5. **New executability** — mode changes can convert inert content into executable content.
6. **Large release deltas** — high-risk mutations are easier to conceal.
7. **Single-identity authorization** — a compromised author should not independently satisfy a configured second-person control.
8. **Evidence replay** — approval for one commit range should not authorize another.

## Review-evidence trust assumptions

ReleaseGuard relies on GitHub's representation of:

- pull-request author and head/base SHAs;
- reviewer login and account type;
- review state, commit ID, and author association; and
- token permission boundaries.

These are platform assertions, not cryptographic identity proof. A compromised GitHub organization owner or repository administrator may be able to alter collaborators, workflow permissions, branch protection, trusted reviewer policy, or the required-check configuration.

## Out of scope for v0.2

ReleaseGuard alone does not prevent:

- direct registry publication with a stolen long-lived token;
- compromise of GitHub, the package registry, runner image, or operating system;
- malicious code that is semantically subtle but violates no configured invariant;
- compromise or collusion of every trusted reviewer;
- a project administrator disabling every required control;
- proof that a binary was reproducibly built from reviewed source;
- verification that a published package corresponds to the expected repository and commit; or
- first-class dependency analysis for every package ecosystem.

These are not treated as solved problems.

## Defense in depth

A strong deployment combines ReleaseGuard with:

- protected default and release branches;
- required checks that include ReleaseGuard;
- CODEOWNERS review for workflow, action, policy, and release-script paths;
- protected deployment environments;
- short-lived OIDC/trusted-publishing credentials;
- registry provenance or attestations;
- registry-side MFA and recovery controls;
- pinned third-party Actions; and
- reproducible or isolated release builds where practical.

Future versions will verify more of the registry and provenance evidence directly.
