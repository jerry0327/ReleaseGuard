# Releasing ReleaseGuard

ReleaseGuard releases are evidence-bearing maintenance events, not only version-number changes.

## Preconditions

1. The intended version is identical in `pyproject.toml`, `releaseguard/__init__.py`, `CITATION.cff`, and `CHANGELOG.md`.
2. `python scripts/release_check.py --tag vX.Y.Z` passes.
3. Unit tests pass on every supported Python version.
4. Repository and npm evidence schemas remain compatible or have documented version increments.
5. Third-party Actions remain pinned to reviewed full commit SHAs.
6. Security-sensitive changes have an explicit review record.
7. The changelog states added, changed, fixed, security, and known-limitation information as applicable.

## Release procedure

```bash
make check
make test
make build
git tag -s vX.Y.Z -m "ReleaseGuard vX.Y.Z"
git push origin vX.Y.Z
```

Pushing the tag runs `.github/workflows/release.yml`, which revalidates the tag/version relationship, runs tests, builds the wheel and source archive, creates SHA-256 checksums, and publishes a GitHub Release.

A maintainer can rerun the workflow for an existing tag through `workflow_dispatch`; it does not create or move tags.

## GitHub Action version aliases

Consumers should pin a full ReleaseGuard commit SHA. Moving major/minor aliases, if introduced later, must be updated only after the immutable release tag succeeds and must never precede it.

## Failure handling

Do not move or overwrite a published release tag. Correct release defects with a new patch version. If an artifact or release note is materially wrong, document the incident and replacement version rather than silently rewriting history.
