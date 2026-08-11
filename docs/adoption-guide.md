# Adoption guide

ReleaseGuard is intended to become stricter in stages. Enabling every control immediately on a mature repository can create avoidable noise and encourage unsafe blanket exceptions.

## Stage 1 — observe critical release mutations

Use the default threshold and keep review evidence disabled:

```toml
[releaseguard]
fail_on = "critical"

[releaseguard.review]
minimum_independent_approvals = 0
```

At this stage, install-time npm execution and non-registry dependency redirection block. High, medium, and low findings remain visible in the job summary and evidence artifacts.

Recommended duration: enough release PRs to understand expected workflow, binary, and dependency findings.

## Stage 2 — enforce high-risk release controls

After intentional paths are represented in policy:

```toml
[releaseguard]
fail_on = "high"
```

This blocks protected release-control changes, unexpected binaries, executable-bit introductions, release hooks, and new production dependency surface.

Do not solve recurring findings by broad patterns such as `"**"`. Keep allowlists narrow and document why a path contains reviewed binary content.

## Stage 3 — require independent review

Grant `pull-requests: read`, pass `github-token`, then enable a quorum:

```toml
[releaseguard.review]
minimum_independent_approvals = 1
required_on = "high"
allow_stale_approvals = false
exclude_bots = true
fail_closed = true
allowed_author_associations = ["OWNER", "MEMBER", "COLLABORATOR"]
```

Test this in a pull request that intentionally changes a protected path. Confirm that:

1. the action reports `RG012` before approval;
2. author self-approval is excluded;
3. an authorized collaborator's fresh approval is counted; and
4. pushing another commit makes the prior approval stale unless the repository itself dismisses or revalidates it first.

## Stage 4 — integrate release protections

ReleaseGuard is strongest alongside platform controls:

- require the ReleaseGuard job before merge or deployment;
- protect default and release branches;
- require review for CODEOWNERS paths;
- protect the publishing environment;
- use short-lived trusted-publishing/OIDC credentials;
- retain JSON and SARIF evidence with release records; and
- pin third-party actions to reviewed commit SHAs.

## Monorepos

v0.2 evaluates one repository-wide range and recognizes root-level package manifests. For monorepos with multiple package boundaries:

- tune protected path patterns now;
- avoid assuming root manifest rules cover every package; and
- track first-class monorepo package-boundary support on the roadmap.

## Offline and local scans

Local scans work without GitHub access when review quorum is zero or no finding reaches the review trigger. When a quorum is required, provide repository/PR context and a token through `RELEASEGUARD_GITHUB_TOKEN`.

For an intentionally offline check, use a separate local configuration with `minimum_independent_approvals = 0` rather than weakening the repository's CI policy.
