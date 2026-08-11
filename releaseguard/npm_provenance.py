from __future__ import annotations

import time

from .models import NpmVerificationResult, SEVERITY_RANK
from .npm_attestations import (
    IN_TOTO_RELEASE_V01,
    NPM_PUBLISH_V01,
    SLSA_V02,
    SLSA_V1,
)
from .npm_internal import VerificationRequest
from .npm_policy import evaluate_verified_identity
from .npm_registry import read_registry_metadata
from .npm_runtime import (
    CommandResult,
    DEFAULT_BUILDER,
    DEFAULT_REGISTRY,
    MIN_NPM_VERSION,
    Runner,
    Sleeper,
    _default_runner,
    _normalize_registry,
    _normalize_repository,
    _normalize_workflow,
    _parse_npm_version,
    _safe_detail,
    _validate_commit,
    _validate_identity_uri,
    _validate_package,
    _validate_ref,
    _validate_version,
)
from .npm_verify import verify_registry_artifact

__all__ = [
    "CommandResult",
    "DEFAULT_BUILDER",
    "DEFAULT_REGISTRY",
    "IN_TOTO_RELEASE_V01",
    "NPM_PUBLISH_V01",
    "SLSA_V02",
    "SLSA_V1",
    "verify_npm_package",
]


def _verify_once(
    request: VerificationRequest,
    *,
    attempt: int,
) -> NpmVerificationResult:
    metadata = read_registry_metadata(request, attempt=attempt)
    if isinstance(metadata, NpmVerificationResult):
        return metadata

    artifact = verify_registry_artifact(request, metadata, attempt=attempt)
    if isinstance(artifact, NpmVerificationResult):
        return artifact

    return evaluate_verified_identity(request, artifact, attempt=attempt)


def verify_npm_package(
    package: str,
    version: str,
    *,
    expected_repository: str,
    expected_workflow: str,
    expected_commit: str,
    expected_ref: str | None = None,
    expected_builder: str = DEFAULT_BUILDER,
    registry: str = DEFAULT_REGISTRY,
    require_trusted_publisher: bool = True,
    fail_on: str = "high",
    npm_executable: str = "npm",
    attempts: int = 1,
    retry_delay: float = 5.0,
    timeout: float = 180.0,
    runner: Runner = _default_runner,
    sleeper: Sleeper = time.sleep,
) -> NpmVerificationResult:
    """Verify one exact published npm version and its expected GitHub identity."""

    package = _validate_package(package)
    version = _validate_version(version)
    repository = _normalize_repository(expected_repository)
    workflow = _normalize_workflow(expected_workflow)
    commit = _validate_commit(expected_commit)
    ref = _validate_ref(expected_ref)
    registry = _normalize_registry(registry)
    if fail_on not in SEVERITY_RANK:
        raise ValueError("fail_on must be one of: low, medium, high, critical")
    expected_builder = _validate_identity_uri(expected_builder)
    if not npm_executable or "\x00" in npm_executable:
        raise ValueError("npm executable must be a non-empty path or command name")
    if isinstance(attempts, bool) or not isinstance(attempts, int) or not 1 <= attempts <= 20:
        raise ValueError("attempts must be an integer between 1 and 20")
    if retry_delay < 0 or retry_delay > 300:
        raise ValueError("retry_delay must be between 0 and 300 seconds")
    if timeout < 5 or timeout > 1800:
        raise ValueError("timeout must be between 5 and 1800 seconds")

    request = VerificationRequest(
        package=package,
        version=version,
        registry=registry,
        expected_repository=repository,
        expected_workflow=workflow,
        expected_commit=commit,
        expected_ref=ref,
        expected_builder=expected_builder,
        require_trusted_publisher=require_trusted_publisher,
        fail_on=fail_on,
        npm_executable=npm_executable,
        timeout=timeout,
        runner=runner,
    )

    last: NpmVerificationResult | None = None
    for attempt in range(1, attempts + 1):
        last = _verify_once(request, attempt=attempt)
        rule_ids = {finding.rule_id for finding in last.findings}
        retryable = (
            last.evidence.status in {"missing", "unavailable"}
            or bool(rule_ids & {"RG018", "RG025"})
        )

        # An old or malformed npm version is deterministic and will not become
        # verification-capable by waiting for registry propagation.
        if last.evidence.status == "unavailable" and last.evidence.npm_version is not None:
            parsed = _parse_npm_version(last.evidence.npm_version)
            if parsed is None or parsed < MIN_NPM_VERSION:
                retryable = False

        if not retryable or attempt == attempts:
            return last
        sleeper(retry_delay)

    assert last is not None
    return last
