from __future__ import annotations

from typing import Any

from . import __version__
from .models import Finding, NpmProvenanceEvidence, NpmVerificationResult, SEVERITY_RANK
from .npm_internal import VerificationRequest
from .npm_runtime import (
    NpmVerificationError,
    _manifest_metadata,
    _publisher_fields,
    _sanitize_url_for_evidence,
)

def _sort_findings(findings: list[Finding]) -> tuple[Finding, ...]:
    return tuple(
        sorted(
            findings,
            key=lambda item: (-SEVERITY_RANK[item.severity], item.rule_id, item.path or ""),
        )
    )


def _finding(
    rule_id: str,
    severity: str,
    title: str,
    detail: str,
    remediation: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        title=title,
        detail=detail,
        path="npm-registry",
        remediation=remediation,
    )


def _base_evidence(
    *,
    status: str,
    npm_version: str | None,
    registry: str,
    package: str,
    version: str,
    attempts: int,
    manifest: dict[str, Any] | None = None,
    detail: str | None = None,
) -> NpmProvenanceEvidence:
    dist: dict[str, Any] = {}
    trusted: dict[str, Any] | None = None
    if manifest is not None:
        try:
            dist, trusted = _manifest_metadata(manifest)
        except NpmVerificationError:
            dist = {}
    publisher_id, config_id = _publisher_fields(trusted)
    attestations = dist.get("attestations")
    attestation_url = attestations.get("url") if isinstance(attestations, dict) and isinstance(attestations.get("url"), str) else None
    return NpmProvenanceEvidence(
        status=status,
        verifier="npm audit signatures --json --include-attestations",
        npm_version=npm_version,
        registry=registry,
        package=package,
        version=version,
        attempts=attempts,
        manifest_integrity=dist.get("integrity") if isinstance(dist.get("integrity"), str) else None,
        tarball_url=_sanitize_url_for_evidence(dist.get("tarball")),
        attestation_url=_sanitize_url_for_evidence(attestation_url),
        trusted_publisher_id=publisher_id,
        trusted_publisher_oidc_config_id=config_id,
        detail=detail,
    )


def _result(
    *,
    package: str,
    version: str,
    registry: str,
    expected_repository: str,
    expected_workflow: str,
    expected_commit: str,
    expected_ref: str | None,
    expected_builder: str,
    require_trusted_publisher: bool,
    findings: list[Finding],
    fail_on: str,
    evidence: NpmProvenanceEvidence,
) -> NpmVerificationResult:
    return NpmVerificationResult(
        package=package,
        version=version,
        registry=registry,
        expected_repository=expected_repository,
        expected_workflow=expected_workflow,
        expected_commit=expected_commit,
        expected_ref=expected_ref,
        expected_builder=expected_builder,
        require_trusted_publisher=require_trusted_publisher,
        findings=_sort_findings(findings),
        fail_on=fail_on,
        tool_version=__version__,
        evidence=evidence,
    )


def _unavailable_result(
    *,
    package: str,
    version: str,
    registry: str,
    expected_repository: str,
    expected_workflow: str,
    expected_commit: str,
    expected_ref: str | None,
    expected_builder: str,
    require_trusted_publisher: bool,
    fail_on: str,
    npm_version: str | None,
    attempts: int,
    detail: str,
    manifest: dict[str, Any] | None = None,
) -> NpmVerificationResult:
    evidence = _base_evidence(
        status="unavailable",
        npm_version=npm_version,
        registry=registry,
        package=package,
        version=version,
        attempts=attempts,
        manifest=manifest,
        detail=detail,
    )
    return _result(
        package=package,
        version=version,
        registry=registry,
        expected_repository=expected_repository,
        expected_workflow=expected_workflow,
        expected_commit=expected_commit,
        expected_ref=expected_ref,
        expected_builder=expected_builder,
        require_trusted_publisher=require_trusted_publisher,
        fail_on=fail_on,
        evidence=evidence,
        findings=[
            _finding(
                "RG017",
                "critical",
                "npm cryptographic verifier unavailable",
                detail,
                "Use a current npm CLI, restore registry connectivity, and rerun verification before release promotion.",
            )
        ],
    )


def _result_for_request(
    request: VerificationRequest,
    *,
    evidence: NpmProvenanceEvidence,
    findings: list[Finding],
) -> NpmVerificationResult:
    return _result(
        package=request.package,
        version=request.version,
        registry=request.registry,
        expected_repository=request.expected_repository,
        expected_workflow=request.expected_workflow,
        expected_commit=request.expected_commit,
        expected_ref=request.expected_ref,
        expected_builder=request.expected_builder,
        require_trusted_publisher=request.require_trusted_publisher,
        findings=findings,
        fail_on=request.fail_on,
        evidence=evidence,
    )


def _unavailable_for_request(
    request: VerificationRequest,
    *,
    npm_version: str | None,
    attempt: int,
    detail: str,
    manifest: dict[str, Any] | None = None,
) -> NpmVerificationResult:
    return _unavailable_result(
        package=request.package,
        version=request.version,
        registry=request.registry,
        expected_repository=request.expected_repository,
        expected_workflow=request.expected_workflow,
        expected_commit=request.expected_commit,
        expected_ref=request.expected_ref,
        expected_builder=request.expected_builder,
        require_trusted_publisher=request.require_trusted_publisher,
        fail_on=request.fail_on,
        npm_version=npm_version,
        attempts=attempt,
        detail=detail,
        manifest=manifest,
    )
