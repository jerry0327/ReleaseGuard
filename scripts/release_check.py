from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
PIN_RE = re.compile(r"@[0-9a-f]{40}$")
USES_RE = re.compile(r"^\s*uses:\s*([^\s#]+)", re.MULTILINE)


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def _project_version() -> str:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        document = tomllib.load(handle)
    return str(document["project"]["version"])


def _value(pattern: str, text: str, label: str) -> str:
    match = re.search(pattern, text, re.MULTILINE)
    if not match:
        raise ValueError(f"could not read {label}")
    return match.group(1)


def _action_files() -> list[Path]:
    paths = list((ROOT / ".github" / "workflows").glob("*.yml"))
    paths.extend((ROOT / ".github" / "workflows").glob("*.yaml"))
    paths.append(ROOT / "action.yml")
    paths.extend((ROOT / "actions").glob("**/action.yml"))
    return sorted({path for path in paths if path.exists()})


def _check_action_pins(errors: list[str]) -> None:
    for path in _action_files():
        text = path.read_text(encoding="utf-8")
        for reference in USES_RE.findall(text):
            if reference.startswith("./"):
                continue
            if not PIN_RE.search(reference):
                errors.append(
                    f"{path.relative_to(ROOT)} uses an unpinned external action: {reference}"
                )


def run(tag: str | None = None) -> list[str]:
    errors: list[str] = []
    version = _project_version()

    init_version = _value(
        r'^__version__\s*=\s*"([^"]+)"',
        _read("releaseguard/__init__.py"),
        "releaseguard.__version__",
    )
    citation_version = _value(
        r"^version:\s*([^\s]+)",
        _read("CITATION.cff"),
        "CITATION.cff version",
    )
    if init_version != version:
        errors.append(f"releaseguard.__version__ is {init_version}; pyproject is {version}")
    if citation_version != version:
        errors.append(f"CITATION.cff version is {citation_version}; pyproject is {version}")
    if f"## [{version}]" not in _read("CHANGELOG.md"):
        errors.append(f"CHANGELOG.md has no [{version}] release section")
    if tag is not None and tag != f"v{version}":
        errors.append(f"release tag {tag!r} must equal v{version}")

    required = (
        "README.md",
        "LICENSE",
        "SECURITY.md",
        "SUPPORT.md",
        "CONTRIBUTING.md",
        "CODE_OF_CONDUCT.md",
        "GOVERNANCE.md",
        "MAINTAINERS.md",
        "RELEASING.md",
        "CHANGELOG.md",
        "CITATION.cff",
        "docs/threat-model.md",
        "docs/project-brief.md",
        "schemas/releaseguard-report.schema.json",
        "schemas/npm-provenance-report.schema.json",
    )
    for relative in required:
        if not (ROOT / relative).is_file():
            errors.append(f"required release file is missing: {relative}")

    _check_action_pins(errors)
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate ReleaseGuard release readiness")
    parser.add_argument("--tag", help="optional vX.Y.Z release tag to validate")
    args = parser.parse_args(argv)
    errors = run(args.tag)
    if errors:
        print("Release readiness checks failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print(f"ReleaseGuard {_project_version()} release readiness checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
