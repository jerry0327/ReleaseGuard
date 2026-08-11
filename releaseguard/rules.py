from __future__ import annotations

from fnmatch import fnmatch
import re
from typing import Any, Callable

from .config import PolicyConfig
from .git import read_json_at_ref
from .models import Change, Finding

DANGEROUS_INSTALL_HOOKS = ("preinstall", "install", "postinstall")
RELEASE_HOOKS = ("prepare", "prepublish", "prepublishOnly")
DEPENDENCY_SECTIONS = ("dependencies", "optionalDependencies", "peerDependencies", "devDependencies")
REMOTE_DEP_RE = re.compile(r"^(?:git\+|git://|https?://|file:|link:|github:|gitlab:|bitbucket:)", re.I)
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")


def _matches(path: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch(path, pattern) for pattern in patterns)


def _changed_paths(changes: list[Change]) -> set[str]:
    return {change.path for change in changes}


def protected_path_findings(changes: list[Change], config: PolicyConfig) -> list[Finding]:
    findings: list[Finding] = []
    for change in changes:
        if _matches(change.path, config.protected_patterns):
            findings.append(
                Finding(
                    rule_id="RG001",
                    severity="high",
                    title="Release-control file changed",
                    detail="A file that can alter CI, ownership, or release behavior changed in this release delta.",
                    path=change.path,
                    remediation="Require an independent review of this file and verify the release workflow before publishing.",
                )
            )
    return findings


def binary_findings(changes: list[Change], config: PolicyConfig) -> list[Finding]:
    findings: list[Finding] = []
    for change in changes:
        if change.is_binary and not _matches(change.path, config.allowed_binary_patterns):
            findings.append(
                Finding(
                    rule_id="RG002",
                    severity="high",
                    title="Unexpected binary content changed",
                    detail="Binary changes are difficult to review from a source diff and can conceal executable payloads.",
                    path=change.path,
                    remediation="Rebuild the artifact from reviewed source in CI, or explicitly allow a reviewed binary path.",
                )
            )
    return findings


def executable_findings(changes: list[Change], _: PolicyConfig) -> list[Finding]:
    findings: list[Finding] = []
    for change in changes:
        old_exec = bool(change.old_mode and change.old_mode.endswith("755"))
        new_exec = bool(change.new_mode and change.new_mode.endswith("755"))
        if new_exec and not old_exec:
            findings.append(
                Finding(
                    rule_id="RG003",
                    severity="high",
                    title="Executable bit introduced",
                    detail="A file became executable in the release delta.",
                    path=change.path,
                    remediation="Verify why execution is required and review the complete file content before release.",
                )
            )
    return findings


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def package_json_findings(
    changes: list[Change],
    config: PolicyConfig,
    base: str,
    head: str,
    reader: Callable[[str, str], dict[str, Any] | None] = read_json_at_ref,
) -> list[Finding]:
    paths = _changed_paths(changes)
    if "package.json" not in paths:
        return []

    before = reader(base, "package.json") or {}
    after = reader(head, "package.json") or {}
    findings: list[Finding] = []

    before_scripts = _dict(before.get("scripts"))
    after_scripts = _dict(after.get("scripts"))
    for hook in DANGEROUS_INSTALL_HOOKS:
        if after_scripts.get(hook) and after_scripts.get(hook) != before_scripts.get(hook):
            findings.append(
                Finding(
                    rule_id="RG004",
                    severity="critical",
                    title=f"npm lifecycle hook changed: {hook}",
                    detail=f"The '{hook}' script can execute automatically during package installation.",
                    path="package.json",
                    remediation="Require explicit security review; prefer removing install-time execution from published packages.",
                )
            )

    for hook in RELEASE_HOOKS:
        if after_scripts.get(hook) and after_scripts.get(hook) != before_scripts.get(hook):
            findings.append(
                Finding(
                    rule_id="RG005",
                    severity="high",
                    title=f"npm release lifecycle hook changed: {hook}",
                    detail=f"The '{hook}' script can modify release artifacts around publish time.",
                    path="package.json",
                    remediation="Review the hook and confirm release artifacts are generated reproducibly in CI.",
                )
            )

    for section in DEPENDENCY_SECTIONS:
        before_deps = _dict(before.get(section))
        after_deps = _dict(after.get(section))
        for name, spec in after_deps.items():
            if before_deps.get(name) == spec:
                continue
            if isinstance(spec, str) and REMOTE_DEP_RE.search(spec):
                findings.append(
                    Finding(
                        rule_id="RG006",
                        severity="critical",
                        title="Non-registry dependency source introduced",
                        detail=f"{section}.{name} now resolves from '{spec}', bypassing the normal registry version model.",
                        path="package.json",
                        remediation="Pin dependencies to an expected registry version or independently verify and lock the remote source.",
                    )
                )
            elif name not in before_deps:
                severity = "medium" if section == "devDependencies" else "high"
                findings.append(
                    Finding(
                        rule_id="RG007",
                        severity=severity,
                        title="New direct dependency introduced",
                        detail=f"{name} was added to {section} with spec '{spec}'.",
                        path="package.json",
                        remediation="Verify package provenance, maintainer history, and the resulting lockfile before release.",
                    )
                )

    old_version = before.get("version")
    new_version = after.get("version")
    if isinstance(new_version, str) and new_version != old_version:
        if not SEMVER_RE.match(new_version):
            findings.append(
                Finding(
                    rule_id="RG008",
                    severity="low",
                    title="Version is not conventional SemVer",
                    detail=f"package.json version changed to '{new_version}'.",
                    path="package.json",
                    remediation="Confirm the versioning scheme is intentional.",
                )
            )
        if config.changelog_paths and not any(path in paths for path in config.changelog_paths):
            findings.append(
                Finding(
                    rule_id="RG009",
                    severity="medium",
                    title="Version changed without changelog update",
                    detail=f"package.json version changed from '{old_version}' to '{new_version}' but no configured changelog changed.",
                    path="package.json",
                    remediation="Document the release delta in a configured changelog before publishing.",
                )
            )

    return findings


def manifest_lock_findings(changes: list[Change], config: PolicyConfig) -> list[Finding]:
    paths = _changed_paths(changes)
    manifest_changed = [path for path in config.manifest_paths if path in paths]
    lock_changed = [path for path in config.lockfile_paths if path in paths]
    if manifest_changed and not lock_changed:
        return [
            Finding(
                rule_id="RG010",
                severity="low",
                title="Manifest changed without a lockfile update",
                detail=f"Changed manifest(s): {', '.join(manifest_changed)}. No configured lockfile changed.",
                remediation="If this project commits a lockfile, regenerate it in a trusted environment and include it in the release PR.",
            )
        ]
    return []


def size_findings(changes: list[Change], config: PolicyConfig) -> list[Finding]:
    if len(changes) <= config.max_changed_files:
        return []
    return [
        Finding(
            rule_id="RG011",
            severity="medium",
            title="Release delta is unusually large",
            detail=f"{len(changes)} files changed; configured maximum is {config.max_changed_files}.",
            remediation="Split the release or perform an explicit high-scrutiny review of the full delta.",
        )
    ]


def run_rules(
    changes: list[Change],
    config: PolicyConfig,
    base: str,
    head: str,
    reader: Callable[[str, str], dict[str, Any] | None] = read_json_at_ref,
) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(protected_path_findings(changes, config))
    findings.extend(binary_findings(changes, config))
    findings.extend(executable_findings(changes, config))
    findings.extend(package_json_findings(changes, config, base, head, reader))
    findings.extend(manifest_lock_findings(changes, config))
    findings.extend(size_findings(changes, config))
    return sorted(findings, key=lambda item: (-{"low": 1, "medium": 2, "high": 3, "critical": 4}[item.severity], item.rule_id, item.path or ""))
