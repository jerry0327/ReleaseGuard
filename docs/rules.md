# Rules and rationale

ReleaseGuard rule IDs are stable identifiers. Before 1.0, wording and severity may be refined, but an incompatible semantic replacement requires documentation and versioning.

## Repository and npm-manifest rules

| Rule | Severity | Meaning |
|---|---:|---|
| `RG001` | High | Release-control, ownership, workflow, Action, or publish configuration changed |
| `RG002` | High | Unexpected binary content changed outside configured allowed paths |
| `RG003` | High | A file gained executable mode |
| `RG004` | Critical | npm `preinstall`, `install`, or `postinstall` changed |
| `RG005` | High | npm prepare/publish lifecycle hook changed |
| `RG006` | Critical | npm dependency changed to Git, URL, file, or link source |
| `RG007` | High/Medium | New direct npm dependency introduced |
| `RG008` | Low | npm version is not conventional SemVer |
| `RG009` | Medium | Version changed without configured changelog update |
| `RG010` | Low | Manifest changed without a configured lockfile change |
| `RG011` | Medium | Release delta exceeds configured changed-file limit |

## Review authorization

| Rule | Severity | Meaning |
|---|---:|---|
| `RG012` | Critical | Fresh independent-review quorum was not met |
| `RG013` | Critical/High | Required GitHub review evidence was unavailable |
| `RG014` | Critical | Review evidence and scanned commit range do not match |

## Published npm provenance

| Rule | Severity | Meaning |
|---|---:|---|
| `RG015` | High | Exact npm version does not advertise provenance |
| `RG016` | Critical | npm rejected the target registry signature or attestation |
| `RG017` | Critical | Required npm cryptographic verifier was unavailable |
| `RG018` | High | Expected GitHub trusted-publisher marker is missing or incomplete |
| `RG019` | Critical | Verified provenance names another repository |
| `RG020` | Critical | Verified provenance names another workflow |
| `RG021` | Critical | Verified provenance names another source commit |
| `RG022` | High | Verified provenance names another branch or tag ref |
| `RG023` | Critical | Verified provenance names another builder |
| `RG024` | Critical | Verified statement is malformed, conflicting, or unsupported |
| `RG025` | High | Recognized registry publish/release attestation is missing |

## Python packaging

| Rule | Severity | Meaning |
|---|---:|---|
| `RG026` | Critical | PEP 508, Poetry, or build requirement now uses a URL, VCS, or local path |
| `RG027` | High/Medium | New direct Python runtime or optional/development dependency introduced |
| `RG028` | High | Python build backend or build requirement changed |
| `RG029` | Medium | Dependency fields became dynamically supplied by a backend |

`RG026` is emitted for direct-source changes even when the dependency already existed. `RG027` is limited to newly introduced names. Optional, documentation, test, and development groups use medium severity by default.

## Cargo packaging

| Rule | Severity | Meaning |
|---|---:|---|
| `RG030` | Critical | Cargo dependency now uses Git or a local path |
| `RG031` | High/Medium | New Cargo dependency introduced across runtime, dev, build, workspace, or target sections |
| `RG032` | High | `build.rs`, `package.build`, or native `links` execution metadata changed |
| `RG033` | Critical | Custom registry, `[patch]`, or `[replace]` source override introduced |
| `RG034` | Critical | Changed Python/Cargo TOML could not be parsed, preventing safe inspection |

Cargo development dependencies use medium severity. Build dependencies remain high because they execute inside the release/build trust boundary.

## False-positive strategy

ReleaseGuard intentionally reports high-leverage changes that are often legitimate. The expected response is review and documented policy—not broad suppression. Allow patterns should remain narrow, and a project should preserve evidence explaining why a binary path, source override, dynamic dependency source, or build script is trusted.

## Severity model

- **Critical** — direct execution, source redirection, identity mismatch, cryptographic rejection, or inability to inspect an explicitly supported security boundary.
- **High** — release-control, build-time execution, opaque artifact, production dependency, or required-evidence risk.
- **Medium** — optional/development dependency or release-consistency signal requiring deliberate review.
- **Low** — hygiene or consistency signal with substantial legitimate project variation.
