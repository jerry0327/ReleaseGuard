from __future__ import annotations

import re

from .models import NpmProvenanceEvidence, NpmVerificationResult
from .npm_attestations import IN_TOTO_V01, IN_TOTO_V1
from .npm_internal import VerificationRequest, VerifiedArtifact
from .npm_results import _finding, _result_for_request
from .npm_runtime import _expected_purl, _normalize_workflow, _sanitize_url_for_evidence


def evaluate_verified_identity(
    request: VerificationRequest,
    artifact: VerifiedArtifact,
    *,
    attempt: int,
) -> NpmVerificationResult:
    """Compare npm-verified SLSA claims with the expected release identity."""

    metadata = artifact.metadata
    claims = artifact.claims
    findings = list(metadata.findings)

    if claims.statement_type not in {IN_TOTO_V1, IN_TOTO_V01}:
        findings.append(
            _finding(
                "RG024",
                "critical",
                "npm attestation metadata is malformed",
                f"Unsupported in-toto statement type: {claims.statement_type or 'missing'}.",
                "Upgrade ReleaseGuard only after reviewing the new attestation format and its security semantics.",
            )
        )

    expected_subject = _expected_purl(request.package, request.version)
    if claims.subject_name != expected_subject:
        findings.append(
            _finding(
                "RG024",
                "critical",
                "npm attestation metadata is malformed",
                (
                    f"Expected signed subject {expected_subject}, but provenance names "
                    f"{claims.subject_name or 'no subject'}."
                ),
                "Do not promote the release; inspect the verified statement and package identity.",
            )
        )
    if not isinstance(claims.subject_sha512, str) or not re.fullmatch(
        r"[0-9a-fA-F]{128}", claims.subject_sha512
    ):
        findings.append(
            _finding(
                "RG024",
                "critical",
                "npm attestation metadata is malformed",
                "The verified provenance subject did not contain a canonical SHA-512 hex digest.",
                "Do not promote the release; inspect registry integrity and the verified statement structure.",
            )
        )

    if claims.repository != request.expected_repository:
        findings.append(
            _finding(
                "RG019",
                "critical",
                "npm provenance repository mismatch",
                (
                    f"Expected {request.expected_repository}, but verified provenance names "
                    f"{claims.repository or 'no repository'}."
                ),
                "Do not promote the release; publish from the configured repository or correct the expected identity.",
            )
        )

    normalized_claim_workflow = None
    if claims.workflow:
        try:
            normalized_claim_workflow = _normalize_workflow(claims.workflow)
        except ValueError:
            normalized_claim_workflow = claims.workflow
    if normalized_claim_workflow != request.expected_workflow:
        findings.append(
            _finding(
                "RG020",
                "critical",
                "npm provenance workflow mismatch",
                (
                    f"Expected {request.expected_workflow}, but verified provenance names "
                    f"{claims.workflow or 'no workflow'}."
                ),
                "Restrict trusted publishing to the intended workflow and republish from that workflow.",
            )
        )

    if claims.commit_sha != request.expected_commit:
        findings.append(
            _finding(
                "RG021",
                "critical",
                "npm provenance commit mismatch",
                (
                    f"Expected commit {request.expected_commit}, but verified provenance names "
                    f"{claims.commit_sha or 'no commit'}."
                ),
                "Do not promote the release; verify the published version was built from the intended Git commit.",
            )
        )

    if request.expected_ref is not None and claims.ref != request.expected_ref:
        findings.append(
            _finding(
                "RG022",
                "high",
                "npm provenance ref mismatch",
                (
                    f"Expected ref {request.expected_ref}, but verified provenance names "
                    f"{claims.ref or 'no ref'}."
                ),
                "Confirm the release branch/tag policy and publish from the expected ref.",
            )
        )

    if claims.builder_id != request.expected_builder:
        findings.append(
            _finding(
                "RG023",
                "critical",
                "npm provenance builder mismatch",
                (
                    f"Expected builder {request.expected_builder}, but verified provenance names "
                    f"{claims.builder_id or 'no builder'}."
                ),
                "Use the reviewed GitHub-hosted release environment or explicitly configure and review another builder identity.",
            )
        )

    if not artifact.publish_attestation_types:
        findings.append(
            _finding(
                "RG025",
                "high",
                "npm registry publish attestation is missing",
                "The verified bundle contains build provenance but no recognized npm registry publish/release attestation.",
                "Confirm the registry accepted and attested the published artifact before promotion.",
            )
        )

    evidence = NpmProvenanceEvidence(
        status="verified",
        verifier="npm audit signatures --json --include-attestations",
        npm_version=metadata.npm_version,
        registry=request.registry,
        package=request.package,
        version=request.version,
        attempts=attempt,
        manifest_integrity=(
            metadata.dist.get("integrity")
            if isinstance(metadata.dist.get("integrity"), str)
            else None
        ),
        tarball_url=_sanitize_url_for_evidence(metadata.dist.get("tarball")),
        attestation_url=_sanitize_url_for_evidence(metadata.attestations.get("url")),
        trusted_publisher_id=metadata.publisher_id,
        trusted_publisher_oidc_config_id=metadata.publisher_config_id,
        statement_type=claims.statement_type,
        predicate_type=claims.predicate_type,
        verified_attestation_types=artifact.verified_attestation_types,
        publish_attestation_types=artifact.publish_attestation_types,
        subject_name=claims.subject_name,
        subject_sha512=claims.subject_sha512,
        repository=claims.repository,
        workflow=claims.workflow,
        commit_sha=claims.commit_sha,
        ref=claims.ref,
        builder_id=claims.builder_id,
        invocation_id=_sanitize_url_for_evidence(claims.invocation_id),
        detail=(
            "npm CLI cryptographically verified the target package attestations "
            "before ReleaseGuard evaluated identity claims."
        ),
    )
    return _result_for_request(request, evidence=evidence, findings=findings)
