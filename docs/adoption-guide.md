# Adoption guide

Adopt ReleaseGuard in stages so legitimate project patterns become explicit policy rather than broad exceptions.

## Stage 1 — observe critical repository mutations

```toml
[releaseguard]
fail_on = "critical"

[releaseguard.review]
minimum_independent_approvals = 0
```

Install-time npm execution, non-registry npm dependencies, Python URL/VCS/path dependencies, Cargo Git/path/source overrides, and uninspectable changed TOML block by default.

## Stage 2 — enforce high-risk release surfaces

```toml
[releaseguard]
fail_on = "high"
```

This adds protected workflow/ownership changes, binaries, executable bits, build backend changes, Cargo build scripts, production dependencies, and npm provenance-policy failures.

Keep binary and path allowlists narrow. Do not use `"**"` merely to silence recurring findings.

## Stage 3 — require independent review

Grant `pull-requests: read`, pass `github-token`, and configure a positive quorum. Test author self-approval, stale approval after a new commit, and an authorized collaborator's fresh approval.

## Stage 4 — adopt npm trusted publishing

Configure the exact GitHub repository and workflow as the npm trusted publisher, grant `id-token: write` only to the publishing job, remove reusable publish tokens, and publish from a protected release path.

## Stage 5 — verify the published npm artifact

Run `actions/verify-npm` after publication and before deployment or announcement. Keep JSON and SARIF artifacts with `if: always()` so blocked releases retain evidence.

## Stage 6 — operationalize release governance

Require:

- ReleaseGuard and CI checks before merge;
- CODEOWNERS review for workflows, Actions, policy, schemas, and release scripts;
- `make check` and `make test` before tagging;
- immutable `vX.Y.Z` tags;
- the automated release workflow and checksums; and
- documented handling of security-sensitive changes.

## Monorepos

Repository scanning remains repository-wide. Root `pyproject.toml` and `Cargo.toml` are analyzed; package-specific npm verification runs once per published package. First-class package-boundary policy remains roadmap work.

## Offline and private-registry use

Repository scanning is offline-capable. npm provenance verification is online and supports public or anonymously readable registries in the current release. Do not inject private registry credentials; the verifier intentionally strips them.
