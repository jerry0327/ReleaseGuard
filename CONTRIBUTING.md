# Contributing to ReleaseGuard

ReleaseGuard is a security-sensitive project. Contributions should favor small, auditable changes with explicit tests and threat-model reasoning.

## Local development

Requirements: Git and Python 3.11+.

```bash
git clone https://github.com/jerry0327/ReleaseGuard.git
cd ReleaseGuard
python -m unittest discover -s tests -v
python -m releaseguard --help
```

The runtime intentionally has no third-party Python dependencies. Please discuss new runtime dependencies before adding them.

## Adding or changing a rule

A rule change should include:

1. a stable `RGxxx` identifier;
2. a defined attacker behavior or release invariant;
3. severity and rationale;
4. a remediation message;
5. positive and negative tests; and
6. documentation changes when policy behavior changes.

Avoid rules that merely assign a vague "AI risk score" without deterministic evidence.

## Pull requests

Keep PRs focused. Explain the threat scenario, expected false positives, and how the change was tested. Security-relevant changes to `.github/workflows`, `action.yml`, ownership configuration, or release scripts receive extra scrutiny by design.

## Reporting bugs

Ordinary bugs can use GitHub Issues. Do not include exploit details for a vulnerability in a public issue; follow [SECURITY.md](SECURITY.md) instead.
