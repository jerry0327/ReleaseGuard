# Architecture

ReleaseGuard v0.2 separates deterministic repository analysis from optional GitHub evidence enrichment.

```text
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
```

## Modules

- `releaseguard/git.py` — resolves commit ranges and extracts changed paths, binary markers, and file modes from Git.
- `releaseguard/config.py` — parses TOML policy with Python's standard library.
- `releaseguard/rules.py` — deterministic repository and package rules.
- `releaseguard/github_evidence.py` — narrow GitHub REST client, PR context parser, review trust filtering, and range binding.
- `releaseguard/models.py` — stable finding, result, and review-evidence data structures.
- `releaseguard/report.py` — human-readable summary and JSON report writing.
- `releaseguard/sarif.py` — SARIF 2.1.0 output and deterministic fingerprints.
- `releaseguard/cli.py` — CLI and composite-action boundary.

## Network boundary

The deterministic scan requires no network request. GitHub API access occurs only when:

1. the configured approval count is greater than zero; and
2. a deterministic finding reaches the configured review trigger.

The client:

- accepts HTTPS API origins, with HTTP limited to localhost tests;
- sends the token only in the authorization header;
- uses a versioned GitHub REST API header;
- limits a response to 4 MiB;
- limits review pagination to ten pages; and
- returns sanitized errors that do not include credentials or response bodies.

## Trust boundary

GitHub review evidence is treated as authorization metadata, not as proof of source correctness. ReleaseGuard filters by independence, latest decisive state, commit freshness, bot status, and reviewer trust context before counting an approval.

The repository administrator still controls workflow permissions, branch protection, trusted reviewer configuration, and whether ReleaseGuard is required. An administrator who can disable every independent control remains outside the v0.2 security boundary.

## Output boundary

The JSON report is the complete ReleaseGuard evidence record. SARIF is an interoperable presentation format for findings; it does not replace the JSON review-evidence object or determine the exit code.
