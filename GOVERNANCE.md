# Governance

ReleaseGuard is currently a maintainer-led open-source project.

## Decision model

The primary maintainer is accountable for roadmap, security posture, compatibility, and releases. Decisions should be made in public issues or pull requests when disclosure is safe. Security vulnerabilities remain private until a fix and coordinated disclosure are ready.

Changes are evaluated against four questions:

1. What attacker behavior or maintainer burden does the change address?
2. What deterministic evidence supports the decision?
3. What false positives, compatibility risks, or new trust dependencies are introduced?
4. How is the behavior tested and documented?

## Security-sensitive changes

Changes to workflows, Actions, policy schemas, evidence parsers, credential boundaries, release automation, or CODEOWNERS require explicit security review. Third-party Actions must be pinned to reviewed full commit SHAs.

The project does not use an LLM as the PASS/BLOCK authority. Optional model-assisted explanations must remain separable from deterministic enforcement.

## Compatibility

Before 1.0, interfaces may evolve, but breaking JSON schema, CLI, rule-meaning, or SARIF-fingerprint changes require a version increment and changelog entry. Stable rule IDs should not be repurposed for unrelated semantics.

## Contributions and disputes

Technical disagreement should be resolved with reproducible examples, tests, specifications, and threat-model analysis. The primary maintainer makes the final decision when consensus is unavailable and records the rationale in the relevant issue or pull request.

## Project integrity

Stars, downloads, deployments, contributors, and funding are reported only when supported by verifiable evidence. The project will not fabricate adoption to improve a grant or support application.
