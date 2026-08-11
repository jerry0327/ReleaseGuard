# Adoption guide

ReleaseGuard should become stricter in stages. Enabling every control immediately on a mature repository can create avoidable noise and encourage unsafe blanket exceptions.

## Stage 1 — observe critical repository mutations

Use the default repository threshold and keep review evidence disabled:

```toml
[releaseguard]
fail_on = "critical"

[releaseguard.review]
minimum_independent_approvals = 0
```

Install-time npm execution and non-registry dependency redirection block. High, medium, and low findings remain visible.

## Stage 2 — enforce high-risk release controls

After intentional paths are represented in policy:

```toml
[releaseguard]
fail_on = "high"
```

This blocks protected release-control changes, unexpected binaries, executable-bit introductions, release hooks, and new production dependency surface.

Do not solve recurring findings with broad patterns such as `"**"`. Keep allowlists narrow and document why each path is trusted.

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

Test with a pull request that intentionally changes a protected path. Confirm that author self-approval and stale approval do not count.

## Stage 4 — adopt npm trusted publishing

Before adding the post-publish gate:

1. configure npm trusted publishing for the exact GitHub organization/user, repository, and workflow;
2. grant `id-token: write` only to the publishing job;
3. remove reusable npm publish tokens from that workflow;
4. use an exact package version from `package.json`; and
5. publish from a protected branch/tag and environment as appropriate.

Use current Node.js/npm versions supported by trusted publishing and provenance.

## Stage 5 — add the post-publish npm gate

Run `actions/verify-npm` after publication and before deployment, announcement, image build, or other promotion:

```yaml
- uses: jerry0327/ReleaseGuard/actions/verify-npm@main
  with:
    package: ${{ steps.package.outputs.name }}
    version: ${{ steps.package.outputs.version }}
    repository: ${{ github.repository }}
    workflow: .github/workflows/publish.yml
    commit: ${{ github.sha }}
    ref: ${{ github.ref }}
```

The default Action policy blocks every npm finding at high or critical severity. Keep the default trusted-publisher requirement unless a deliberate migration still uses token-published provenance.

Registry evidence can lag publication. The Action retries six times by default. Do not replace a persistent failure with an unconditional `continue-on-error` in the promotion path.

## Stage 6 — retain and optionally attest evidence

Upload both JSON and SARIF with `if: always()` so blocked releases retain diagnostic evidence.

A separate first-party GitHub artifact-attestation step can sign the JSON report. This signs the evidence file; it does not change the underlying npm verification result.

## Platform controls

ReleaseGuard is strongest alongside:

- required checks;
- protected branches and tags;
- CODEOWNERS for workflows, Actions, policy, and release scripts;
- protected deployment environments;
- short-lived OIDC credentials;
- pinned third-party Actions;
- package ownership/MFA/recovery controls; and
- retained release evidence.

## Monorepos

Repository scanning remains repository-wide. npm verification evaluates one exact package/version per invocation. Call the npm Action once per published package and pass the package-specific expected release identity.

First-class monorepo package-boundary policy remains roadmap work.

## Offline and private-registry use

Repository scanning is offline-capable. npm provenance verification is necessarily online and currently supports public or anonymously readable registries only.

Do not inject a private registry token into `verify-npm`; v0.3 intentionally strips credentials at the subprocess boundary.
