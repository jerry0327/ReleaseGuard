# Security policy

## Supported versions

ReleaseGuard is currently pre-1.0. Security fixes are applied to the latest development line.

## Reporting a vulnerability

Please prefer GitHub's **private vulnerability reporting** / Security Advisory flow for this repository when available.

If private reporting is not available, open a public issue containing only a request for a private security contact. Do **not** post exploit details, secrets, proof-of-concept payloads, or an unpatched vulnerability description publicly.

A useful private report includes:

- affected ReleaseGuard version or commit;
- the release-policy bypass or unsafe behavior;
- minimal reproduction steps;
- expected security boundary; and
- any proposed mitigation.

## Security boundary

ReleaseGuard evaluates repository and release evidence. It does not claim to secure registry credentials, GitHub accounts, runner infrastructure, or the package registry itself. See [docs/threat-model.md](docs/threat-model.md).
