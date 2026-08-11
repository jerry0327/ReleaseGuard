# Independent review evidence

ReleaseGuard can require independent approval when the deterministic release scan reaches a configured severity. This control addresses a specific threat: one compromised maintainer identity should not be sufficient to introduce and approve a high-risk release mutation.

## Enabling the gate

```toml
[releaseguard.review]
minimum_independent_approvals = 1
required_on = "high"
allow_stale_approvals = false
exclude_bots = true
fail_closed = true
allowed_author_associations = ["OWNER", "MEMBER", "COLLABORATOR"]
trusted_reviewers = []
```

The GitHub Actions job must grant read access and pass the workflow token:

```yaml
permissions:
  contents: read
  pull-requests: read

steps:
  - uses: jerry0327/ReleaseGuard@main
    with:
      github-token: ${{ github.token }}
```

The token is read from the action input into an environment variable. ReleaseGuard does not accept a token as a CLI argument and does not include it in reports or errors.

## When review evidence is required

Review evidence is evaluated only when both conditions are true:

1. `minimum_independent_approvals` is greater than zero; and
2. at least one deterministic finding is at or above `required_on`.

A low-risk documentation-only release therefore does not require API access merely because a review policy exists.

## Effective review state

GitHub returns reviews chronologically. ReleaseGuard keeps the latest **decisive** review for each login:

- `APPROVED` can count;
- `CHANGES_REQUESTED` prevents that reviewer's earlier approval from counting;
- `DISMISSED` prevents the dismissed approval from counting; and
- `COMMENTED` and `PENDING` are not decisive and do not erase an existing approval.

This avoids treating a follow-up comment as approval revocation while still honoring a later explicit request for changes.

## Independence and trust

An approval is excluded when any of the following applies:

- the reviewer is the pull-request author;
- the reviewer is a bot and `exclude_bots = true`;
- the review targets another commit and `allow_stale_approvals = false`; or
- the reviewer is neither in an allowed `author_association` nor explicitly listed in `trusted_reviewers`.

The default trusted associations are:

- `OWNER`
- `MEMBER`
- `COLLABORATOR`

Public drive-by approvals are therefore not treated as security authorization. A project can explicitly trust an external auditor by login:

```toml
trusted_reviewers = ["external-security-auditor"]
```

`trusted_reviewers` should be used sparingly and reviewed like any other release-control policy.

## Commit-range binding

ReleaseGuard resolves the scanned refs to full commit SHAs. Before accepting approvals it compares:

- the scanned head SHA with the event and current pull-request head SHA; and
- the scanned base SHA with the event base SHA, or with the current PR base when no event base is available.

A mismatch produces `RG014`. This prevents a workflow from scanning one range while presenting approvals obtained for another.

## Failure modes

| Condition | Finding | Default behavior |
|---|---|---|
| Approval count below quorum | `RG012` | Critical / block |
| Token, PR context, or API evidence unavailable | `RG013` | Critical when `fail_closed = true` |
| Scanned range does not match PR range | `RG014` | Critical / block |

When `fail_closed = false`, unavailable evidence is reported as high severity instead of critical. An explicitly unmet quorum or a range mismatch remains critical.

## Evidence retained

The JSON report records logins only in the following categories:

- counted approvals;
- stale approvals;
- self-approvals;
- bot approvals;
- untrusted approvals; and
- reviewers whose latest decisive state is `CHANGES_REQUESTED`.

Review bodies and inline comments are not collected. This keeps the evidence narrow and avoids retaining unrelated discussion content.

## Known limitations

- GitHub author association is a repository-context signal, not cryptographic proof of reviewer identity.
- A compromised organization owner may still modify branch protection, workflow permissions, or ReleaseGuard policy.
- Review evidence does not replace protected branches or protected deployment environments.
- Review approval alone does not prove a package registry accepted the expected artifact. Registry provenance is separate roadmap work.
