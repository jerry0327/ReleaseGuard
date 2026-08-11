# Security policy

## Supported versions

ReleaseGuard is pre-1.0. Security fixes are applied to the latest development line. Users should pin the action to a reviewed commit SHA and update after reviewing security releases.

## Reporting a vulnerability

Prefer GitHub's **private vulnerability reporting** / Security Advisory flow for this repository when available.

If private reporting is unavailable, open a public issue containing only a request for a private security contact. Do **not** post exploit details, secrets, proof-of-concept payloads, token values, or an unpatched vulnerability description publicly.

A useful private report includes:

- affected ReleaseGuard version or commit;
- the release-policy bypass or unsafe behavior;
- minimal reproduction steps;
- expected security boundary;
- whether credentials or untrusted repository content are involved; and
- any proposed mitigation.

## Security boundary

ReleaseGuard evaluates repository and selected GitHub review evidence. It does not claim to secure registry credentials, GitHub accounts, runner infrastructure, the package registry, or every project administrator action. See [docs/threat-model.md](docs/threat-model.md).

## Credential handling

The optional GitHub token is accepted through `RELEASEGUARD_GITHUB_TOKEN`, `GITHUB_TOKEN`, or the composite action's `github-token` input. ReleaseGuard does not accept it as a CLI argument, include it in reports, or include GitHub response bodies in error messages.
