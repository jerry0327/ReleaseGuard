# Funding and API-credit plan

ReleaseGuard's core PASS/BLOCK path is deterministic and does not require an OpenAI API. API credits would support maintainer work around that security boundary, not replace it.

## Proposed uses

### 1. Maintainer triage and review assistance

Use Codex and API-backed automation to summarize issue reproductions, map reports to rule IDs, identify affected modules/tests, and draft focused pull-request review checklists. A maintainer remains responsible for decisions and merges.

### 2. Adversarial fixture generation

Generate diverse, non-malicious test fixtures for PEP 508, TOML, Cargo target sections, npm/SLSA schema variants, malformed evidence, and platform edge cases. Fixtures would be reviewed, minimized, and committed as deterministic regression tests.

### 3. Compatibility analysis

Analyze upstream specification and tool changes, propose compatibility matrices, and prepare candidate patches when npm, PyPI, GitHub Actions, SLSA, in-toto, or package-manager output formats evolve.

### 4. Documentation and release operations

Draft migration notes, release summaries, rule-reference updates, and contributor guidance from reviewed code changes. Automate consistency checks between findings, schemas, examples, and documentation.

### 5. Optional explanations

Explore opt-in explanations for multi-file findings. Model output would be advisory, clearly labeled, and never required for ReleaseGuard to pass or block a release.

## Guardrails

- No source or evidence is sent to an external model without an explicit workflow choice.
- Secrets, credentials, raw private review content, and raw cryptographic bundles are excluded.
- Deterministic findings and tests remain the source of truth.
- Generated patches require normal review and CI.
- Usage and cost are logged by task category so credits can be evaluated against maintainer impact.

## Expected outcome

Credits would reduce the time required to triage compatibility reports, expand adversarial test coverage, maintain evolving ecosystem integrations, and produce safer releases—while preserving a local, inspectable enforcement core.
