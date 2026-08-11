# Releasing ReleaseGuard

ReleaseGuard releases are evidence-bearing maintenance events, not only version-number changes.

## Preconditions

1. The intended version is identical in `pyproject.toml`, `releaseguard/__init__.py`, `CITATION.cff`, and `CHANGELOG.md`.
2. `python scripts/release_check.py --tag vX.Y.Z` passes.
3. Unit tests pass on every supported Python version.
4. Repository and npm evidence schemas remain compatible or have documented version increments.
5. Third-party Actions remain pinned to reviewed full commit SHAs.
6. Security-sensitive changes have an explicit review record.
7. The intended commit is the current, green `main` commit.

## Automated owner-only release bootstrap

Creating a branch named `release/vX.Y.Z` at the exact current `main` commit triggers `.github/workflows/release.yml`.

The workflow:

1. runs only when the branch push actor is the repository owner;
2. rejects a bootstrap branch that does not equal the current `main` commit;
3. validates the version/tag relationship and full test suite;
4. creates an immutable annotated `vX.Y.Z` tag if it does not already exist;
5. builds the wheel and source archive;
6. creates `SHA256SUMS`;
7. publishes the GitHub Release; and
8. removes the temporary bootstrap branch.

The bootstrap path is useful when repository automation can create branches but cannot create Git tag objects directly. It does not pretend the automatically created annotated tag has a maintainer GPG signature; the tagged commit itself should be a verified, reviewed merge commit.

## Manual signed-tag alternative

A maintainer with local signing and Git push access may instead run:

```bash
make check
make test
make build
git tag -s vX.Y.Z -m "ReleaseGuard vX.Y.Z"
git push origin vX.Y.Z
```

Pushing the tag runs the same release workflow. `workflow_dispatch` can rerun an existing tag; it never moves or replaces a tag.

## GitHub Action version aliases

Consumers should pin a full ReleaseGuard commit SHA. Moving major/minor aliases, if introduced later, must be updated only after the immutable release tag succeeds and must never precede it.

## Failure handling

Do not move or overwrite a published release tag. Correct release defects with a new patch version. If an artifact or release note is materially wrong, document the incident and replacement version rather than silently rewriting history.
