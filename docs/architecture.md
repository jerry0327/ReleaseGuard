# Architecture

ReleaseGuard separates pre-release repository analysis from post-publish registry verification.

```text
PRE-RELEASE

Git history / GitHub event
          |
          v
   commit range resolver
          |
          v
     git delta reader
          |
          +---- paths / modes / binary markers
          |
          v
 deterministic rule engine <---- releaseguard.toml
          |
          +---- high-risk trigger? ---- no ----+
          |                                    |
         yes                                   |
          |                                    |
          v                                    |
 GitHub PR + review evidence                    |
          |                                    |
          +---- range binding / trust filter --+
                                               |
                                               v
                                           ScanResult
                                         /      |      \
                                        v       v       v
                                  JSON evidence SARIF  job summary

POST-PUBLISH

exact npm package@version
          |
          v
 validated registry metadata
          |
          v
 isolated credential-free npm sandbox
          |
          v
 official npm signature/attestation verifier
          |
          v
 verified target-package DSSE statements
          |
          v
 SLSA claim normalization + identity policy
          |
          v
                                  NpmVerificationResult
                                         /      |      \
                                        v       v       v
                                  JSON evidence SARIF  job summary
```

## Modules

- `releaseguard/git.py` — resolves ranges and extracts changed paths, binary markers, and modes.
- `releaseguard/config.py` — parses repository/review TOML policy using the standard library.
- `releaseguard/rules.py` — deterministic repository and package-manifest rules.
- `releaseguard/github_evidence.py` — GitHub PR context, review trust filtering, and range binding.
- `releaseguard/npm_runtime.py` — exact input validation, credential-free npm environment, bounded subprocess execution, and registry metadata normalization.
- `releaseguard/npm_attestations.py` — verified DSSE decoding plus SLSA v1/v0.2 claim normalization.
- `releaseguard/npm_results.py` — stable npm findings, evidence assembly, and unavailable-verifier results.
- `releaseguard/npm_provenance.py` — post-publish verification orchestration and expected-identity policy.
- `releaseguard/models.py` — finding, scan, review, npm evidence, and result structures.
- `releaseguard/report.py` — JSON and human-readable summaries.
- `releaseguard/sarif.py` — repository and npm SARIF 2.1.0 output with separately versioned fingerprints.
- `releaseguard/cli.py` — CLI and composite-Action integration boundary.

## Network boundaries

### Repository scan

The deterministic Git scan requires no network. GitHub API access occurs only when a positive review quorum is configured and a finding reaches its review trigger.

### npm verification

`verify-npm` requires registry, Sigstore/TUF, and transparency-log access through npm. It does not perform direct unauthenticated Sigstore verification in Python.

The npm subprocess receives an allowlisted environment containing process discovery, locale, proxy, and certificate settings. Credentials, arbitrary Node options, inherited npm configuration, and caller HOME/cache state are excluded.

## Cryptographic boundary

npm is responsible for validating:

- registry signatures and keys;
- Sigstore bundles;
- signing certificate chains;
- transparency-log evidence;
- package PURL subject; and
- package SHA-512 subject digest.

ReleaseGuard accepts source claims only from the target package records npm returns as verified. It then independently checks supported statement structure, canonical subject form, and expected release identity.

This avoids two unsafe extremes:

- treating registry JSON presence as proof; and
- implementing a partial, divergent cryptographic verifier in a dependency-free Python project.

## Evidence boundary

Repository scan and npm provenance reports use different schemas because they represent different evidence objects.

- repository report: schema version 2
- npm provenance report: schema version 1
- repository SARIF fingerprint: `releaseguard/v1`
- npm SARIF fingerprint: `releaseguard/npm-v1`

Raw review discussion and raw cryptographic bundles are excluded from durable reports. Optional report signing can be performed by a separate first-party GitHub artifact-attestation step.
