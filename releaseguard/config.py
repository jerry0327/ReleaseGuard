from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import tomllib

from .models import SEVERITY_RANK


@dataclass(frozen=True)
class PolicyConfig:
    fail_on: str = "critical"
    max_changed_files: int = 200
    changelog_paths: tuple[str, ...] = ("CHANGELOG.md",)
    manifest_paths: tuple[str, ...] = ("package.json", "pyproject.toml", "Cargo.toml")
    lockfile_paths: tuple[str, ...] = (
        "package-lock.json",
        "npm-shrinkwrap.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "uv.lock",
        "poetry.lock",
        "Cargo.lock",
    )
    protected_patterns: tuple[str, ...] = (
        ".github/workflows/**",
        ".github/CODEOWNERS",
        "CODEOWNERS",
        ".npmrc",
        "action.yml",
        "scripts/release/**",
    )
    allowed_binary_patterns: tuple[str, ...] = ("docs/**", "assets/**")


def _tuple_of_strings(value: object, key: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{key} must be an array of strings")
    return tuple(value)


def load_config(path: str | Path | None) -> PolicyConfig:
    if not path:
        return PolicyConfig()

    file_path = Path(path)
    if not file_path.exists():
        return PolicyConfig()

    with file_path.open("rb") as handle:
        raw = tomllib.load(handle)

    section = raw.get("releaseguard", {})
    if not isinstance(section, dict):
        raise ValueError("[releaseguard] must be a TOML table")

    defaults = PolicyConfig()
    fail_on = str(section.get("fail_on", defaults.fail_on)).lower()
    if fail_on not in SEVERITY_RANK:
        raise ValueError("fail_on must be one of: low, medium, high, critical")

    max_changed_files = int(section.get("max_changed_files", defaults.max_changed_files))
    if max_changed_files < 1:
        raise ValueError("max_changed_files must be at least 1")

    def pick(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
        if name not in section:
            return default
        return _tuple_of_strings(section[name], name)

    return PolicyConfig(
        fail_on=fail_on,
        max_changed_files=max_changed_files,
        changelog_paths=pick("changelog_paths", defaults.changelog_paths),
        manifest_paths=pick("manifest_paths", defaults.manifest_paths),
        lockfile_paths=pick("lockfile_paths", defaults.lockfile_paths),
        protected_patterns=pick("protected_patterns", defaults.protected_patterns),
        allowed_binary_patterns=pick("allowed_binary_patterns", defaults.allowed_binary_patterns),
    )
