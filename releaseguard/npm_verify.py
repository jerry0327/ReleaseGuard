from __future__ import annotations

import json
from pathlib import Path
import tempfile

from .models import NpmVerificationResult
from .npm_attestations import _extract_claims
from .npm_internal import RegistryMetadata, VerificationRequest, VerifiedArtifact
from .npm_results import _base_evidence, _finding, _result_for_request, _unavailable_for_request
from .npm_runtime import (
    NpmVerificationError,
    _audit_target_records,
    _json_object,
    _safe_detail,
    _safe_environment,
)


def _invalid_crypto_result(
    request: VerificationRequest,
    metadata: RegistryMetadata,
    *,
    attempt: int,
    detail: str,
    findings: list,
) -> NpmVerificationResult:
    evidence = _base_evidence(
        status="invalid",
        npm_version=metadata.npm_version,
        registry=request.registry,
        package=request.package,
        version=request.version,
        attempts=attempt,
        manifest=metadata.manifest,
        detail=detail,
    )
    findings.append(
        _finding(
            "RG016",
            "critical",
            "npm attestation verification failed",
            detail,
            "Do not consume or promote the package; investigate registry signatures, attestation integrity, and publication history.",
        )
    )
    return _result_for_request(request, evidence=evidence, findings=findings)


def verify_registry_artifact(
    request: VerificationRequest,
    metadata: RegistryMetadata,
    *,
    attempt: int,
) -> VerifiedArtifact | NpmVerificationResult:
    """Run npm's maintained cryptographic verifier in an isolated project."""

    findings = list(metadata.findings)
    with tempfile.TemporaryDirectory(prefix="releaseguard-npm-") as directory:
        root = Path(directory)
        env = _safe_environment(root, request.registry)
        project = root / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "releaseguard-npm-verification-sandbox",
                    "version": "0.0.0",
                    "private": True,
                }
            )
            + "\n",
            encoding="utf-8",
        )

        install_args = [
            request.npm_executable,
            "install",
            "--ignore-scripts",
            "--bin-links=false",
            "--audit=false",
            "--fund=false",
            "--package-lock=true",
            "--save-exact=true",
            "--omit=optional",
            f"--registry={request.registry}",
            request.target,
        ]
        try:
            install_result = request.runner(install_args, project, env, request.timeout)
        except NpmVerificationError as exc:
            return _unavailable_for_request(
                request,
                npm_version=metadata.npm_version,
                attempt=attempt,
                detail=str(exc),
                manifest=metadata.manifest,
            )
        if install_result.returncode != 0:
            return _unavailable_for_request(
                request,
                npm_version=metadata.npm_version,
                attempt=attempt,
                detail=_safe_detail(
                    install_result.stderr,
                    f"npm could not install {request.target} in the isolated verification sandbox",
                ),
                manifest=metadata.manifest,
            )

        audit_args = [
            request.npm_executable,
            "audit",
            "signatures",
            "--json",
            "--include-attestations",
            "--omit=dev",
            "--omit=optional",
            f"--registry={request.registry}",
        ]
        try:
            audit_result = request.runner(audit_args, project, env, request.timeout)
            audit = _json_object(audit_result.stdout, label="npm audit signatures")
            verified, invalid, missing = _audit_target_records(
                audit,
                request.package,
                request.version,
            )
        except NpmVerificationError as exc:
            return _unavailable_for_request(
                request,
                npm_version=metadata.npm_version,
                attempt=attempt,
                detail=str(exc),
                manifest=metadata.manifest,
            )

        if invalid or missing:
            codes = sorted(
                {
                    str(item.get("code", "missing-registry-signature"))
                    for item in [*invalid, *missing]
                }
            )
            return _invalid_crypto_result(
                request,
                metadata,
                attempt=attempt,
                detail=(
                    f"npm cryptographic verification rejected {request.target}: "
                    f"{', '.join(codes)}."
                ),
                findings=findings,
            )

        if not verified:
            return _invalid_crypto_result(
                request,
                metadata,
                attempt=attempt,
                detail=(
                    "npm audit signatures did not return a cryptographically verified "
                    f"attestation bundle for {request.target}."
                ),
                findings=findings,
            )

        try:
            claims, verified_types, publish_types = _extract_claims(verified)
        except NpmVerificationError as exc:
            evidence = _base_evidence(
                status="invalid",
                npm_version=metadata.npm_version,
                registry=request.registry,
                package=request.package,
                version=request.version,
                attempts=attempt,
                manifest=metadata.manifest,
                detail=str(exc),
            )
            findings.append(
                _finding(
                    "RG024",
                    "critical",
                    "npm attestation metadata is malformed",
                    str(exc),
                    "Do not promote the release; inspect the verified attestation bundle and supported SLSA predicate format.",
                )
            )
            return _result_for_request(request, evidence=evidence, findings=findings)

        return VerifiedArtifact(
            metadata=metadata,
            claims=claims,
            verified_attestation_types=verified_types,
            publish_attestation_types=publish_types,
        )
