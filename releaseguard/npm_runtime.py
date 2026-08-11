from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import quote, unquote, urlparse

DEFAULT_BUILDER = "https://github.com/actions/runner/github-hosted"
DEFAULT_REGISTRY = "https://registry.npmjs.org"
MIN_NPM_VERSION = (11, 12, 0)
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_STDERR_BYTES = 1024 * 1024
MAX_DSSE_PAYLOAD_BYTES = 2 * 1024 * 1024
MAX_ATTESTATION_BUNDLES = 64

_PACKAGE_RE = re.compile(
    r"^(?:@[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?/[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?|"
    r"[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?)$"
)
_SEMVER_RE = re.compile(
    r"^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_REF_RE = re.compile(r"^refs/(?:heads|tags)/[^\s\x00]+$")
_WORKFLOW_RE = re.compile(r"^\.github/workflows/[A-Za-z0-9._/-]+\.ya?ml$")

@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


Runner = Callable[[Sequence[str], Path, Mapping[str, str], float], CommandResult]
Sleeper = Callable[[float], None]


class NpmVerificationError(RuntimeError):
    """A sanitized operational failure while collecting npm evidence."""

    def __init__(self, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.retryable = retryable


def _default_runner(
    argv: Sequence[str],
    cwd: Path,
    env: Mapping[str, str],
    timeout: float,
) -> CommandResult:
    # Spool subprocess output to temporary files rather than accumulating an
    # unbounded byte stream in memory. Only bounded prefixes are decoded.
    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        try:
            process = subprocess.run(
                list(argv),
                cwd=cwd,
                env=dict(env),
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                timeout=timeout,
                start_new_session=True,
            )
        except FileNotFoundError as exc:
            raise NpmVerificationError("npm executable was not found") from exc
        except subprocess.TimeoutExpired as exc:
            raise NpmVerificationError(
                f"npm command exceeded the {timeout:g}-second timeout",
                retryable=True,
            ) from exc
        except OSError as exc:
            raise NpmVerificationError(f"npm command could not start: {type(exc).__name__}") from exc

        stdout_file.seek(0)
        stdout_bytes = stdout_file.read(MAX_JSON_BYTES + 1)
        if len(stdout_bytes) > MAX_JSON_BYTES:
            raise NpmVerificationError("npm JSON output exceeded the 16 MiB safety limit")

        stderr_file.seek(0)
        stderr_bytes = stderr_file.read(MAX_STDERR_BYTES + 1)
        stderr_truncated = len(stderr_bytes) > MAX_STDERR_BYTES
        stderr_bytes = stderr_bytes[:MAX_STDERR_BYTES]
        stdout = stdout_bytes.decode("utf-8", errors="replace")
        stderr = stderr_bytes.decode("utf-8", errors="replace")
        if stderr_truncated:
            stderr += "\n[stderr truncated by ReleaseGuard]"
        return CommandResult(process.returncode, stdout, stderr)


def _validate_package(package: str) -> str:
    value = package.strip()
    if not _PACKAGE_RE.fullmatch(value):
        raise ValueError(
            "package must be a lowercase npm package name, optionally scoped as @scope/name"
        )
    return value


def _validate_version(version: str) -> str:
    value = version.strip()
    if not _SEMVER_RE.fullmatch(value):
        raise ValueError("version must be an exact SemVer value, not a tag or range")
    return value


def _validate_commit(commit_sha: str) -> str:
    value = commit_sha.strip().lower()
    if not _SHA_RE.fullmatch(value):
        raise ValueError("expected commit must be a full 40-character Git SHA")
    return value


def _validate_ref(ref: str | None) -> str | None:
    if ref is None or not ref.strip():
        return None
    value = ref.strip()
    if not _REF_RE.fullmatch(value):
        raise ValueError("expected ref must use refs/heads/... or refs/tags/... syntax")
    return value


def _normalize_workflow(workflow: str) -> str:
    value = workflow.strip().replace("\\", "/")
    while value.startswith("./"):
        value = value[2:]
    if value.startswith("/") or ".." in value.split("/") or not _WORKFLOW_RE.fullmatch(value):
        raise ValueError("expected workflow must be a .github/workflows/*.yml path")
    return value


def _normalize_repository(value: str) -> str:
    candidate = value.strip()
    if not candidate:
        raise ValueError("expected repository is required")

    candidate = candidate.removeprefix("git+")
    if candidate.startswith("github.com/"):
        candidate = f"https://{candidate}"
    if candidate.startswith("git@github.com:"):
        candidate = "https://github.com/" + candidate[len("git@github.com:") :]

    if "://" in candidate:
        parsed = urlparse(candidate)
        if parsed.hostname is None or parsed.hostname.lower() != "github.com":
            raise ValueError("only github.com repositories are supported in v0.3")
        path = unquote(parsed.path).strip("/")
    else:
        path = candidate.strip("/")

    path = path.removesuffix(".git")
    parts = path.split("/")
    if len(parts) != 2 or not all(re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in parts):
        raise ValueError("repository must use owner/name or a github.com repository URL")
    return f"{parts[0].lower()}/{parts[1].lower()}"


def _normalize_registry(value: str) -> str:
    candidate = value.strip().rstrip("/")
    parsed = urlparse(candidate)
    if parsed.scheme == "https" and parsed.hostname:
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("registry URL must not contain credentials, query, or fragment")
        return candidate
    if parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost"}:
        return candidate
    raise ValueError("registry must use HTTPS; HTTP is allowed only for localhost tests")


def _validate_identity_uri(value: str) -> str:
    candidate = value.strip()
    parsed = urlparse(candidate)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("expected builder must be an HTTPS identity URI without credentials, query, or fragment")
    return candidate


def _sanitize_url_for_evidence(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    parsed = urlparse(value)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname:
        return None
    host = parsed.hostname
    if parsed.port is not None:
        host = f"{host}:{parsed.port}"
    # Never retain userinfo, query parameters, or fragments from registry data.
    return parsed._replace(netloc=host, query="", fragment="").geturl()


def _expected_purl(package: str, version: str) -> str:
    return f"pkg:npm/{quote(package, safe='/')}@{version}"


def _parse_npm_version(value: str) -> tuple[int, int, int] | None:
    match = re.match(r"^\s*(\d+)\.(\d+)\.(\d+)", value)
    if not match:
        return None
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def _safe_detail(stderr: str, fallback: str) -> str:
    first = next((line.strip() for line in stderr.splitlines() if line.strip()), "")
    if not first:
        return fallback
    first = re.sub(
        r"(?i)\b(token|authorization|password|secret)\b\s*=?\s*[^\s]+",
        r"\1=[redacted]",
        first,
    )
    return first[:500]


def _json_object(value: str, *, label: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise NpmVerificationError(f"{label} did not return valid JSON") from exc
    if not isinstance(parsed, dict):
        raise NpmVerificationError(f"{label} returned an unexpected JSON shape")
    return parsed


def _json_manifest(value: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise NpmVerificationError("npm view did not return valid JSON") from exc
    if isinstance(parsed, dict):
        return parsed
    # npm 12 changed `npm view --json` to consistently return an array. Exact
    # versions must still resolve to one manifest.
    if isinstance(parsed, list) and len(parsed) == 1 and isinstance(parsed[0], dict):
        return parsed[0]
    raise NpmVerificationError("npm view returned an unexpected JSON shape")


def _safe_environment(root: Path, registry: str) -> dict[str, str]:
    # npm does not need the caller's GitHub/cloud credentials. Preserve only
    # process discovery, locale, proxy, and certificate settings. This also
    # drops NODE_OPTIONS/NODE_PATH, which could otherwise alter npm execution.
    allowed = {
        "PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT",
        "LANG", "LC_ALL", "LC_CTYPE", "TZ",
        "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY",
        "http_proxy", "https_proxy", "no_proxy", "all_proxy",
        "SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_EXTRA_CA_CERTS",
    }
    env = {key: value for key, value in os.environ.items() if key in allowed}

    home = root / "home"
    cache = root / "cache"
    temp = root / "tmp"
    home.mkdir(parents=True, exist_ok=True)
    cache.mkdir(parents=True, exist_ok=True)
    temp.mkdir(parents=True, exist_ok=True)
    userconfig = root / "user.npmrc"
    globalconfig = root / "global.npmrc"
    userconfig.write_text("", encoding="utf-8")
    globalconfig.write_text("", encoding="utf-8")

    env.update(
        {
            "HOME": str(home),
            "USERPROFILE": str(home),
            "CI": "true",
            "NO_UPDATE_NOTIFIER": "1",
            "NPM_CONFIG_USERCONFIG": str(userconfig),
            "NPM_CONFIG_GLOBALCONFIG": str(globalconfig),
            "NPM_CONFIG_CACHE": str(cache),
            "TMPDIR": str(temp),
            "TEMP": str(temp),
            "TMP": str(temp),
            "NPM_CONFIG_REGISTRY": registry,
            "NPM_CONFIG_AUDIT": "false",
            "NPM_CONFIG_FUND": "false",
            "NPM_CONFIG_IGNORE_SCRIPTS": "true",
            "NPM_CONFIG_UPDATE_NOTIFIER": "false",
            "NPM_CONFIG_PROGRESS": "false",
            "NPM_CONFIG_COLOR": "false",
            "NPM_CONFIG_LOGLEVEL": "error",
        }
    )
    return env


def _target_spec(package: str, version: str) -> str:
    return f"{package}@{version}"


def _manifest_metadata(manifest: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any] | None]:
    dist = manifest.get("dist")
    if not isinstance(dist, dict):
        raise NpmVerificationError("npm manifest did not include a dist object")

    trusted = manifest.get("trustedPublisher")
    npm_user = manifest.get("_npmUser")
    if not isinstance(trusted, dict) and isinstance(npm_user, dict):
        nested = npm_user.get("trustedPublisher")
        trusted = nested if isinstance(nested, dict) else None
    return dist, trusted if isinstance(trusted, dict) else None


def _publisher_fields(trusted: dict[str, Any] | None) -> tuple[str | None, str | None]:
    if trusted is None:
        return None, None
    publisher_id = trusted.get("id")
    config_id = trusted.get("oidcConfigId")
    return (
        publisher_id if isinstance(publisher_id, str) else None,
        config_id if isinstance(config_id, str) else None,
    )


def _audit_target_records(
    payload: dict[str, Any],
    package: str,
    version: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    def items(key: str) -> list[dict[str, Any]]:
        value = payload.get(key, [])
        if not isinstance(value, list):
            raise NpmVerificationError(f"npm audit signatures field '{key}' was not an array")
        return [item for item in value if isinstance(item, dict)]

    def matches(item: dict[str, Any]) -> bool:
        return item.get("name") == package and item.get("version") == version

    return (
        [item for item in items("verified") if matches(item)],
        [item for item in items("invalid") if matches(item)],
        [item for item in items("missing") if matches(item)],
    )
