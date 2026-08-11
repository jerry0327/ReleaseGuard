# Architecture

ReleaseGuard separates pre-release repository analysis, review authorization, and post-publish registry verification.

```text
Git range
   |
   v
path / mode / binary delta
   |
   +--> generic + npm rules
   +--> pyproject.toml / Poetry rules
   +--> Cargo.toml / build.rs rules
   |
   v
review trigger ----> GitHub PR/review evidence ----> exact commit binding
   |                                                   |
   +---------------------------------------------------+
                           |
                           v
                  JSON / SARIF / PASS-BLOCK

exact npm package@version
   |
   v
isolated credential-free npm sandbox
   |
   v
npm cryptographic verifier
   |
   v
verified target-package statements
   |
   v
SLSA claim normalization and expected identity policy
   |
   v
npm JSON / SARIF / PASS-BLOCK
```

## Core modules

- `releaseguard/git.py` — Git range, path, binary, and mode extraction.
- `releaseguard/rules.py` — rule orchestration and npm manifest rules.
- `releaseguard/ecosystems.py` — dependency-free TOML analysis for PEP 621, Poetry, and Cargo.
- `releaseguard/github_evidence.py` — pull-request context, trusted review filtering, and commit binding.
- `releaseguard/npm_runtime.py` — exact npm input validation, bounded subprocess execution, and credential-isolated environment.
- `releaseguard/npm_attestations.py` — verified DSSE decoding and SLSA v1/v0.2 normalization.
- `releaseguard/npm_policy.py` — expected repository, workflow, commit, ref, builder, subject, and publisher policy.
- `releaseguard/models.py` — stable evidence and result structures.
- `releaseguard/report.py` and `releaseguard/sarif.py` — durable JSON, summaries, and SARIF.
- `scripts/release_check.py` — version, governance-file, tag, and external-Action pin validation.

## Parser boundary

Python's standard-library `tomllib` parses supported package manifests. A changed `pyproject.toml` or `Cargo.toml` that cannot be parsed produces critical `RG034`; ReleaseGuard does not silently skip ecosystem analysis.

Dependency records are normalized by section and canonical package name. Existing registry-version changes are not treated as new dependencies, while changes to direct URL/VCS/path sources remain critical.

## Network boundary

Repository scanning is offline. GitHub API access occurs only when independent review is configured and triggered. npm verification requires registry and Sigstore-related access through the official npm CLI.

## Trust boundary

ReleaseGuard does not implement a partial cryptographic verifier. npm remains responsible for registry signatures, certificate chains, transparency-log evidence, package subject, and digest verification. ReleaseGuard accepts claims only from target-package evidence npm reports as verified.

GitHub review metadata and package-manager manifests are platform/project assertions, not proof that source code is benign.

## Release boundary

A release is valid only when version metadata, changelog, governance files, and executable Action pins pass `scripts/release_check.py`. A pushed immutable `vX.Y.Z` tag is rechecked before GitHub Release artifacts and checksums are created.
