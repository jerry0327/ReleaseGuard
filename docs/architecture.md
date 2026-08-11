# Architecture

ReleaseGuard v0.1 is deliberately small.

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
          v
       ScanResult
       /       \
      v         v
 JSON evidence  GitHub job summary
```

## Modules

- `releaseguard/git.py` — resolves commit ranges and extracts changed paths, binary markers, and file modes from Git.
- `releaseguard/config.py` — parses the TOML policy using Python's standard library.
- `releaseguard/rules.py` — deterministic release-risk rules.
- `releaseguard/models.py` — stable internal finding/result data structures.
- `releaseguard/report.py` — JSON evidence and human-readable Markdown output.
- `releaseguard/cli.py` — CLI and GitHub Actions integration boundary.

## Why no service is required

The first security boundary should continue to work if an external API is unavailable. ReleaseGuard therefore requires no network request and no secret for v0.1 scanning.

Future integrations may enrich evidence (review identities, provenance, registry metadata, AI-assisted explanations), but policy should distinguish enrichment failure from deterministic local checks.
