from __future__ import annotations

from dataclasses import dataclass
import re
import tomllib
from typing import Any, Callable

from .git import read_text_at_ref
from .models import Change, Finding

TextReader = Callable[[str, str], str | None]

_PEP508_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
_DIRECT_PREFIXES = (
    "git+",
    "git://",
    "http://",
    "https://",
    "file:",
    "hg+",
    "svn+",
    "bzr+",
    "./",
    "../",
    "/",
)


@dataclass(frozen=True)
class DependencyRecord:
    section: str
    name: str
    spec: object
    severity: str
    direct_source: str | None = None


def _dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _canonical_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _load_toml(
    ref: str,
    path: str,
    reader: TextReader,
) -> tuple[dict[str, Any] | None, str | None]:
    raw = reader(ref, path)
    if raw is None:
        return None, None
    try:
        parsed = tomllib.loads(raw)
    except tomllib.TOMLDecodeError as exc:
        return None, str(exc).splitlines()[0][:300]
    return parsed if isinstance(parsed, dict) else {}, None


def _pep508_map(value: object) -> dict[str, str]:
    if not isinstance(value, list):
        return {}
    dependencies: dict[str, str] = {}
    for item in value:
        if not isinstance(item, str):
            continue
        match = _PEP508_NAME_RE.match(item)
        if match:
            dependencies[_canonical_name(match.group(1))] = item.strip()
    return dependencies


def _string_direct_source(spec: str) -> str | None:
    candidate = spec.strip()
    lower = candidate.lower()
    if lower.startswith(_DIRECT_PREFIXES):
        return candidate
    if " @ " in candidate:
        target = candidate.split(" @ ", 1)[1].strip()
        if target.lower().startswith(_DIRECT_PREFIXES):
            return target
    return None


def _python_direct_source(spec: object) -> str | None:
    if isinstance(spec, str):
        return _string_direct_source(spec)
    if isinstance(spec, dict):
        for key in ("git", "path", "url"):
            value = spec.get(key)
            if isinstance(value, str) and value.strip():
                return f"{key}={value.strip()}"
    return None


def _python_records(document: dict[str, Any]) -> dict[tuple[str, str], DependencyRecord]:
    records: dict[tuple[str, str], DependencyRecord] = {}
    project = _dict(document.get("project"))

    for name, spec in _pep508_map(project.get("dependencies")).items():
        key = ("project.dependencies", name)
        records[key] = DependencyRecord(
            section=key[0],
            name=name,
            spec=spec,
            severity="high",
            direct_source=_python_direct_source(spec),
        )

    optional = _dict(project.get("optional-dependencies"))
    for group, values in optional.items():
        for name, spec in _pep508_map(values).items():
            section = f"project.optional-dependencies.{group}"
            records[(section, name)] = DependencyRecord(
                section=section,
                name=name,
                spec=spec,
                severity="medium",
                direct_source=_python_direct_source(spec),
            )

    poetry = _dict(_dict(document.get("tool")).get("poetry"))
    for name, spec in _dict(poetry.get("dependencies")).items():
        canonical = _canonical_name(str(name))
        if canonical == "python":
            continue
        section = "tool.poetry.dependencies"
        records[(section, canonical)] = DependencyRecord(
            section=section,
            name=canonical,
            spec=spec,
            severity="high",
            direct_source=_python_direct_source(spec),
        )

    for name, spec in _dict(poetry.get("dev-dependencies")).items():
        canonical = _canonical_name(str(name))
        section = "tool.poetry.dev-dependencies"
        records[(section, canonical)] = DependencyRecord(
            section=section,
            name=canonical,
            spec=spec,
            severity="medium",
            direct_source=_python_direct_source(spec),
        )

    groups = _dict(poetry.get("group"))
    for group_name, group_value in groups.items():
        dependencies = _dict(_dict(group_value).get("dependencies"))
        severity = "medium" if str(group_name).lower() in {"dev", "test", "tests", "docs"} else "high"
        for name, spec in dependencies.items():
            canonical = _canonical_name(str(name))
            section = f"tool.poetry.group.{group_name}.dependencies"
            records[(section, canonical)] = DependencyRecord(
                section=section,
                name=canonical,
                spec=spec,
                severity=severity,
                direct_source=_python_direct_source(spec),
            )
    return records


def _python_build_records(document: dict[str, Any]) -> dict[str, str]:
    build_system = _dict(document.get("build-system"))
    return _pep508_map(build_system.get("requires"))


def python_manifest_findings(
    changes: list[Change],
    base: str,
    head: str,
    reader: TextReader = read_text_at_ref,
) -> list[Finding]:
    if not any(change.path == "pyproject.toml" for change in changes):
        return []

    before, _ = _load_toml(base, "pyproject.toml", reader)
    after, error = _load_toml(head, "pyproject.toml", reader)
    if error:
        return [
            Finding(
                rule_id="RG034",
                severity="critical",
                title="Package manifest analysis failed",
                detail=f"pyproject.toml could not be parsed as TOML: {error}",
                path="pyproject.toml",
                remediation="Fix the manifest syntax before release so dependency and build-system changes can be inspected.",
            )
        ]
    if after is None:
        return []

    before = before or {}
    findings: list[Finding] = []
    before_records = _python_records(before)
    after_records = _python_records(after)

    for key, record in after_records.items():
        previous = before_records.get(key)
        if previous is not None and previous.spec == record.spec:
            continue
        if record.direct_source:
            findings.append(
                Finding(
                    rule_id="RG026",
                    severity="critical",
                    title="Python direct URL or local-path dependency introduced",
                    detail=(
                        f"{record.section}.{record.name} now resolves from "
                        f"'{record.direct_source}', outside the normal index version model."
                    ),
                    path="pyproject.toml",
                    remediation="Use an expected package-index version, or independently verify and lock the referenced source.",
                )
            )
        elif previous is None:
            findings.append(
                Finding(
                    rule_id="RG027",
                    severity=record.severity,
                    title="New direct Python dependency introduced",
                    detail=f"{record.name} was added to {record.section} with spec {record.spec!r}.",
                    path="pyproject.toml",
                    remediation="Review package provenance, maintainership, transitive dependencies, and the regenerated lockfile.",
                )
            )

    before_build = _dict(before.get("build-system"))
    after_build = _dict(after.get("build-system"))
    old_backend = before_build.get("build-backend")
    new_backend = after_build.get("build-backend")
    if new_backend != old_backend and new_backend is not None:
        findings.append(
            Finding(
                rule_id="RG028",
                severity="high",
                title="Python build backend changed",
                detail=f"build-system.build-backend changed from {old_backend!r} to {new_backend!r}.",
                path="pyproject.toml",
                remediation="Review the backend's provenance and confirm the release build remains reproducible and isolated.",
            )
        )

    before_requires = _python_build_records(before)
    after_requires = _python_build_records(after)
    for name, spec in after_requires.items():
        previous = before_requires.get(name)
        if previous == spec:
            continue
        direct_source = _python_direct_source(spec)
        if direct_source:
            findings.append(
                Finding(
                    rule_id="RG026",
                    severity="critical",
                    title="Python build dependency uses a direct source",
                    detail=f"build-system.requires entry {name} now resolves from '{direct_source}'.",
                    path="pyproject.toml",
                    remediation="Use a reviewed index version or independently verify and lock the build source.",
                )
            )
        else:
            findings.append(
                Finding(
                    rule_id="RG028",
                    severity="high",
                    title="Python build requirement changed",
                    detail=f"build-system.requires changed {name} from {previous!r} to {spec!r}.",
                    path="pyproject.toml",
                    remediation="Review the build requirement and regenerate release artifacts in an isolated environment.",
                )
            )

    before_dynamic = set(item for item in _dict(before.get("project")).get("dynamic", []) if isinstance(item, str))
    after_dynamic = set(item for item in _dict(after.get("project")).get("dynamic", []) if isinstance(item, str))
    relevant_dynamic = {"dependencies", "optional-dependencies"}
    newly_dynamic = sorted((after_dynamic & relevant_dynamic) - (before_dynamic & relevant_dynamic))
    if newly_dynamic:
        findings.append(
            Finding(
                rule_id="RG029",
                severity="medium",
                title="Python dependencies became dynamically supplied",
                detail=f"pyproject.toml now declares dynamic fields: {', '.join(newly_dynamic)}.",
                path="pyproject.toml",
                remediation="Document and review the backend-specific source that supplies these dependencies during the release build.",
            )
        )
    return findings


def _cargo_direct_source(spec: object) -> tuple[str | None, str | None]:
    if not isinstance(spec, dict):
        return None, None
    for key in ("git", "path"):
        value = spec.get(key)
        if isinstance(value, str) and value.strip():
            return "direct", f"{key}={value.strip()}"
    registry = spec.get("registry")
    if isinstance(registry, str) and registry.strip():
        return "registry", registry.strip()
    return None, None


def _cargo_records(document: dict[str, Any]) -> dict[tuple[str, str], DependencyRecord]:
    records: dict[tuple[str, str], DependencyRecord] = {}

    def add_section(section: str, value: object, severity: str) -> None:
        for name, spec in _dict(value).items():
            canonical = _canonical_name(str(name))
            source_kind, source = _cargo_direct_source(spec)
            direct = f"{source_kind}:{source}" if source_kind and source else None
            records[(section, canonical)] = DependencyRecord(
                section=section,
                name=canonical,
                spec=spec,
                severity=severity,
                direct_source=direct,
            )

    add_section("dependencies", document.get("dependencies"), "high")
    add_section("dev-dependencies", document.get("dev-dependencies"), "medium")
    add_section("build-dependencies", document.get("build-dependencies"), "high")

    workspace = _dict(document.get("workspace"))
    add_section("workspace.dependencies", workspace.get("dependencies"), "high")

    targets = _dict(document.get("target"))
    for target_name, target_value in targets.items():
        target = _dict(target_value)
        add_section(f"target.{target_name}.dependencies", target.get("dependencies"), "high")
        add_section(f"target.{target_name}.dev-dependencies", target.get("dev-dependencies"), "medium")
        add_section(f"target.{target_name}.build-dependencies", target.get("build-dependencies"), "high")
    return records


def _cargo_override_records(document: dict[str, Any]) -> dict[str, object]:
    records: dict[str, object] = {}
    patch = _dict(document.get("patch"))
    for source, values in patch.items():
        for name, spec in _dict(values).items():
            records[f"patch.{source}.{name}"] = spec
    for name, spec in _dict(document.get("replace")).items():
        records[f"replace.{name}"] = spec
    return records


def cargo_manifest_findings(
    changes: list[Change],
    base: str,
    head: str,
    reader: TextReader = read_text_at_ref,
) -> list[Finding]:
    paths = {change.path for change in changes}
    if "Cargo.toml" not in paths and "build.rs" not in paths:
        return []

    findings: list[Finding] = []
    if "build.rs" in paths:
        change = next(change for change in changes if change.path == "build.rs")
        if not change.status.startswith("D"):
            findings.append(
                Finding(
                    rule_id="RG032",
                    severity="high",
                    title="Cargo build script changed",
                    detail="build.rs was added or modified and can execute during downstream builds.",
                    path="build.rs",
                    remediation="Review the complete build script, its inputs, network assumptions, and generated outputs.",
                )
            )

    if "Cargo.toml" not in paths:
        return findings

    before, _ = _load_toml(base, "Cargo.toml", reader)
    after, error = _load_toml(head, "Cargo.toml", reader)
    if error:
        findings.append(
            Finding(
                rule_id="RG034",
                severity="critical",
                title="Package manifest analysis failed",
                detail=f"Cargo.toml could not be parsed as TOML: {error}",
                path="Cargo.toml",
                remediation="Fix the manifest syntax before release so dependency and build-script changes can be inspected.",
            )
        )
        return findings
    if after is None:
        return findings

    before = before or {}
    before_records = _cargo_records(before)
    after_records = _cargo_records(after)
    for key, record in after_records.items():
        previous = before_records.get(key)
        if previous is not None and previous.spec == record.spec:
            continue
        if record.direct_source and record.direct_source.startswith("direct:"):
            findings.append(
                Finding(
                    rule_id="RG030",
                    severity="critical",
                    title="Cargo Git or local-path dependency introduced",
                    detail=f"{record.section}.{record.name} now uses {record.direct_source.removeprefix('direct:')}.",
                    path="Cargo.toml",
                    remediation="Use an expected crates.io version, or independently verify and lock the referenced source revision.",
                )
            )
        elif record.direct_source and record.direct_source.startswith("registry:"):
            findings.append(
                Finding(
                    rule_id="RG033",
                    severity="critical",
                    title="Cargo dependency source override introduced",
                    detail=f"{record.section}.{record.name} now uses custom registry '{record.direct_source.removeprefix('registry:')}'.",
                    path="Cargo.toml",
                    remediation="Review the registry trust boundary and require a locked, documented source configuration.",
                )
            )
        elif previous is None:
            findings.append(
                Finding(
                    rule_id="RG031",
                    severity=record.severity,
                    title="New direct Cargo dependency introduced",
                    detail=f"{record.name} was added to {record.section} with spec {record.spec!r}.",
                    path="Cargo.toml",
                    remediation="Review crate provenance, maintainership, features, build scripts, and the regenerated Cargo.lock.",
                )
            )

    before_overrides = _cargo_override_records(before)
    after_overrides = _cargo_override_records(after)
    for key, spec in after_overrides.items():
        if before_overrides.get(key) == spec:
            continue
        findings.append(
            Finding(
                rule_id="RG033",
                severity="critical",
                title="Cargo source replacement introduced",
                detail=f"{key} changed to {spec!r}, overriding normal registry resolution.",
                path="Cargo.toml",
                remediation="Remove the override or independently verify and pin the replacement source before release.",
            )
        )

    before_package = _dict(before.get("package"))
    after_package = _dict(after.get("package"))
    for key in ("build", "links"):
        old_value = before_package.get(key)
        new_value = after_package.get(key)
        if new_value != old_value and new_value not in (None, False, ""):
            findings.append(
                Finding(
                    rule_id="RG032",
                    severity="high",
                    title="Cargo build-time execution metadata changed",
                    detail=f"package.{key} changed from {old_value!r} to {new_value!r}.",
                    path="Cargo.toml",
                    remediation="Review the associated build script and native-linking behavior before publishing the crate.",
                )
            )
    return findings


def ecosystem_findings(
    changes: list[Change],
    base: str,
    head: str,
    reader: TextReader = read_text_at_ref,
) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(python_manifest_findings(changes, base, head, reader))
    findings.extend(cargo_manifest_findings(changes, base, head, reader))
    return findings
