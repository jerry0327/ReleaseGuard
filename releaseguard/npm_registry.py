from __future__ import annotations

from typing import Any

from .models import NpmProvenanceEvidence, NpmVerificationResult
from .npm_internal import RegistryMetadata, VerificationRequest
from .npm_results import (
    _base_evidence,
    _finding,
    _result_for_request,
    _unavailable_for_request,
)
from .npm_runtime import (
    MIN_NPM_VERSION,
    NpmVerificationError,
    _json_manifest,
    _manifest_metadata,
    _parse_npm_version,
    _publisher_fields,
    _safe_detail,
    _safe_environment,
)


def _invalid_manifest_result(
    request: VerificationRequest,
    *,
    npm_version: str,
    attempt: int,
    manifest: dict[str, Any],
) -> NpmVerificationResult:
    evidence = _base_evidence(
        status="invalid",
        npm_version=npm_version,
        registry=request.registry,
        package=request.package,
        version=request.version,
        attempts=attempt,
        manifest=manifest,
        detail="Registry metadata did not describe the exact requested package and version.",
    )
    return _result_for_request(
        request,
        evidence=evidence,
        findings=[
            _finding(
                "RG024",
                "critical",
                "npm attestation metadata is malformed",
                (
                    f"Requested {request.target}, but registry metadata reported "
                    f"{manifest.get('name')!r}@{manifest.get('version')!r}."
                ),
                "Do not promote the release; investigate registry metadata and package identity.",
            )
        ],
    )


def _missing_provenance_result(
    request: VerificationRequest,
    *,
    npm_version: str,
    attempt: int,
    manifest: dict[str, Any],
    publisher_id: str | None,
    config_id: str | None,
) -> NpmVerificationResult:
    findings = [
        _finding(
            "RG015",
            "high",
            "npm provenance is missing",
            f"{request.target} does not advertise a provenance attestation in registry metadata.",
            "Publish through npm trusted publishing or with verified provenance, then rerun the post-publish gate.",
        )
    ]
    if request.require_trusted_publisher and not (publisher_id == "github" and config_id):
        findings.append(
            _finding(
                "RG018",
                "high",
                "npm trusted publisher is missing",
                f"{request.target} was not marked as published by the expected GitHub trusted publisher.",
                "Configure npm trusted publishing for the exact GitHub repository and workflow, and remove reusable publish tokens.",
            )
        )
    evidence = _base_evidence(
        status="missing",
        npm_version=npm_version,
        registry=request.registry,
        package=request.package,
        version=request.version,
        attempts=attempt,
        manifest=manifest,
        detail="Registry metadata contains no provenance attestation URL.",
    )
    return _result_for_request(request, evidence=evidence, findings=findings)


def read_registry_metadata(
    request: VerificationRequest,
    *,
    attempt: int,
) -> RegistryMetadata | NpmVerificationResult:
    """Validate npm capability and retrieve exact, public registry metadata."""

    # Every request gets a new sandbox root; callers create it and pass the
    # environment indirectly through the runner's cwd. Here the npm version
    # check is deliberately performed before trusting any output shape.
    from pathlib import Path
    import tempfile

    with tempfile.TemporaryDirectory(prefix="releaseguard-npm-metadata-") as directory:
        root = Path(directory)
        env = _safe_environment(root, request.registry)
        try:
            version_result = request.runner(
                [request.npm_executable, "--version"],
                root,
                env,
                min(request.timeout, 30.0),
            )
        except NpmVerificationError as exc:
            return _unavailable_for_request(
                request,
                npm_version=None,
                attempt=attempt,
                detail=str(exc),
            )

        npm_version = version_result.stdout.strip() if version_result.returncode == 0 else None
        parsed_version = _parse_npm_version(npm_version or "")
        if parsed_version is None or parsed_version < MIN_NPM_VERSION:
            required = ".".join(str(part) for part in MIN_NPM_VERSION)
            return _unavailable_for_request(
                request,
                npm_version=npm_version,
                attempt=attempt,
                detail=(
                    f"npm {npm_version or 'unknown'} cannot provide the required full verified "
                    f"attestation bundles; npm {required} or newer is required."
                ),
            )

        try:
            manifest_result = request.runner(
                [
                    request.npm_executable,
                    "view",
                    request.target,
                    "--json",
                    f"--registry={request.registry}",
                ],
                root,
                env,
                request.timeout,
            )
        except NpmVerificationError as exc:
            return _unavailable_for_request(
                request,
                npm_version=npm_version,
                attempt=attempt,
                detail=str(exc),
            )
        if manifest_result.returncode != 0:
            return _unavailable_for_request(
                request,
                npm_version=npm_version,
                attempt=attempt,
                detail=_safe_detail(
                    manifest_result.stderr,
                    f"npm registry metadata for {request.target} could not be retrieved",
                ),
            )

        manifest: dict[str, Any] | None = None
        try:
            manifest = _json_manifest(manifest_result.stdout)
            dist, trusted = _manifest_metadata(manifest)
        except NpmVerificationError as exc:
            return _unavailable_for_request(
                request,
                npm_version=npm_version,
                attempt=attempt,
                detail=str(exc),
                manifest=manifest,
            )

        if manifest.get("name") != request.package or manifest.get("version") != request.version:
            return _invalid_manifest_result(
                request,
                npm_version=npm_version,
                attempt=attempt,
                manifest=manifest,
            )

        publisher_id, config_id = _publisher_fields(trusted)
        attestations = dist.get("attestations")
        if not isinstance(attestations, dict) or not isinstance(attestations.get("url"), str):
            return _missing_provenance_result(
                request,
                npm_version=npm_version,
                attempt=attempt,
                manifest=manifest,
                publisher_id=publisher_id,
                config_id=config_id,
            )

        findings = []
        if request.require_trusted_publisher and not (publisher_id == "github" and config_id):
            findings.append(
                _finding(
                    "RG018",
                    "high",
                    "npm trusted publisher is missing",
                    (
                        f"{request.target} has provenance, but registry metadata does not identify "
                        "GitHub trusted publishing."
                    ),
                    "Configure the package's npm trusted publisher for the expected GitHub repository and workflow.",
                )
            )

        return RegistryMetadata(
            npm_version=npm_version,
            manifest=manifest,
            dist=dist,
            attestations=attestations,
            publisher_id=publisher_id,
            publisher_config_id=config_id,
            findings=tuple(findings),
        )
