from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import tomllib

from .models import SEVERITY_RANK


@dataclass(frozen=True)
class ReviewPolicy:
    minimum_independent_approvals: int = 0
    required_on: str = "high"
    allow_stale_approvals: bool = False
    exclude_bots: bool = True
    fail_closed: bool = True
    allowed_author_associations: tuple[str, ...] = ("OWNER", "MEMBER", "COLLABORATOR")
    trusted_reviewers: tuple[str, ...] = ()


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
    review: ReviewPolicy = ReviewPolicy()


def _tuple_of_strings(value: object, key: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{key} must be an array of strings")
    return tuple(value)


def _bool(value: object, key: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{key} must be true or false")
    return value


def _severity(value: object, key: str) -> str:
    severity = str(value).lower()
    if severity not in SEVERITY_RANK:
        raise ValueError(f"{key} must be one of: low, medium, high, critical")
    return severity


def _review_policy(raw: object) -> ReviewPolicy:
    if raw is None:
        return ReviewPolicy()
    if not isinstance(raw, dict):
        raise ValueError("[releaseguard.review] must be a TOML table")

    defaults = ReviewPolicy()
    minimum = raw.get("minimum_independent_approvals", defaults.minimum_independent_approvals)
    if isinstance(minimum, bool) or not isinstance(minimum, int):
        raise ValueError("minimum_independent_approvals must be an integer")
    if not 0 <= minimum <= 20:
        raise ValueError("minimum_independent_approvals must be between 0 and 20")

    required_on = _severity(raw.get("required_on", defaults.required_on), "review.required_on")
    allow_stale = (
        defaults.allow_stale_approvals
        if "allow_stale_approvals" not in raw
        else _bool(raw["allow_stale_approvals"], "review.allow_stale_approvals")
    )
    exclude_bots = (
        defaults.exclude_bots if "exclude_bots" not in raw else _bool(raw["exclude_bots"], "review.exclude_bots")
    )
    fail_closed = (
        defaults.fail_closed if "fail_closed" not in raw else _bool(raw["fail_closed"], "review.fail_closed")
    )
    associations = (
        defaults.allowed_author_associations
        if "allowed_author_associations" not in raw
        else tuple(item.upper() for item in _tuple_of_strings(raw["allowed_author_associations"], "review.allowed_author_associations"))
    )
    valid_associations = {"OWNER", "MEMBER", "COLLABORATOR", "CONTRIBUTOR", "FIRST_TIMER", "FIRST_TIME_CONTRIBUTOR", "MANNEQUIN", "NONE"}
    if not associations or any(item not in valid_associations for item in associations):
        raise ValueError("review.allowed_author_associations contains an unsupported association")
    trusted_reviewers = (
        defaults.trusted_reviewers
        if "trusted_reviewers" not in raw
        else _tuple_of_strings(raw["trusted_reviewers"], "review.trusted_reviewers")
    )
    return ReviewPolicy(
        minimum_independent_approvals=minimum,
        required_on=required_on,
        allow_stale_approvals=allow_stale,
        exclude_bots=exclude_bots,
        fail_closed=fail_closed,
        allowed_author_associations=associations,
        trusted_reviewers=trusted_reviewers,
    )


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
    fail_on = _severity(section.get("fail_on", defaults.fail_on), "fail_on")

    max_changed_files = section.get("max_changed_files", defaults.max_changed_files)
    if isinstance(max_changed_files, bool) or not isinstance(max_changed_files, int):
        raise ValueError("max_changed_files must be an integer")
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
        review=_review_policy(section.get("review")),
    )
