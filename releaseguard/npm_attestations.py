from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
import json
from typing import Any

from .npm_runtime import (
    MAX_ATTESTATION_BUNDLES,
    MAX_DSSE_PAYLOAD_BYTES,
    NpmVerificationError,
    _normalize_repository,
)

SLSA_V1 = "https://slsa.dev/provenance/v1"
SLSA_V02 = "https://slsa.dev/provenance/v0.2"
IN_TOTO_V1 = "https://in-toto.io/Statement/v1"
IN_TOTO_V01 = "https://in-toto.io/Statement/v0.1"
NPM_PUBLISH_V01 = "https://github.com/npm/attestation/tree/main/specs/publish/v0.1"
IN_TOTO_RELEASE_V01 = "https://in-toto.io/attestation/release/v0.1"

@dataclass(frozen=True)
class ProvenanceClaims:
    statement_type: str
    predicate_type: str
    subject_name: str | None
    subject_sha512: str | None
    repository: str | None
    workflow: str | None
    commit_sha: str | None
    ref: str | None
    builder_id: str | None
    invocation_id: str | None


def _decode_statement(entry: dict[str, Any]) -> dict[str, Any]:
    bundle = entry.get("bundle")
    if not isinstance(bundle, dict):
        raise NpmVerificationError("verified attestation did not include a Sigstore bundle")
    envelope = bundle.get("dsseEnvelope")
    if not isinstance(envelope, dict):
        raise NpmVerificationError("verified Sigstore bundle did not include a DSSE envelope")
    payload = envelope.get("payload")
    if not isinstance(payload, str):
        raise NpmVerificationError("verified DSSE envelope did not include a payload")
    try:
        decoded = base64.b64decode(payload, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise NpmVerificationError("verified DSSE payload was not valid base64") from exc
    if len(decoded) > MAX_DSSE_PAYLOAD_BYTES:
        raise NpmVerificationError("verified DSSE payload exceeded the 2 MiB safety limit")
    try:
        statement = json.loads(decoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NpmVerificationError("verified DSSE payload was not a UTF-8 JSON statement") from exc
    if not isinstance(statement, dict):
        raise NpmVerificationError("verified DSSE statement was not a JSON object")
    return statement


def _subject(statement: dict[str, Any]) -> tuple[str | None, str | None]:
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or not subjects:
        return None, None
    first = subjects[0]
    if not isinstance(first, dict):
        return None, None
    name = first.get("name") if isinstance(first.get("name"), str) else None
    digest = first.get("digest")
    sha512 = digest.get("sha512") if isinstance(digest, dict) and isinstance(digest.get("sha512"), str) else None
    return name, sha512


def _repo_and_ref_from_uri(uri: str | None) -> tuple[str | None, str | None]:
    if not uri:
        return None, None
    candidate = uri
    ref = None
    if "@refs/" in candidate:
        candidate, ref_suffix = candidate.rsplit("@", 1)
        ref = ref_suffix if ref_suffix.startswith("refs/") else None
    try:
        repository = _normalize_repository(candidate)
    except ValueError:
        repository = None
    return repository, ref


def _claims_v1(statement: dict[str, Any]) -> ProvenanceClaims:
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        raise NpmVerificationError("SLSA v1 provenance did not include a predicate object")
    definition = predicate.get("buildDefinition")
    run_details = predicate.get("runDetails")
    if not isinstance(definition, dict) or not isinstance(run_details, dict):
        raise NpmVerificationError("SLSA v1 provenance omitted buildDefinition or runDetails")

    external = definition.get("externalParameters")
    workflow = external.get("workflow") if isinstance(external, dict) else None
    if not isinstance(workflow, dict):
        raise NpmVerificationError("SLSA v1 provenance omitted externalParameters.workflow")

    repository_raw = workflow.get("repository")
    repository = None
    if isinstance(repository_raw, str):
        try:
            repository = _normalize_repository(repository_raw)
        except ValueError:
            repository = None
    workflow_path = workflow.get("path") if isinstance(workflow.get("path"), str) else None
    ref = workflow.get("ref") if isinstance(workflow.get("ref"), str) else None

    commit = None
    dependencies = definition.get("resolvedDependencies")
    if isinstance(dependencies, list):
        preferred: list[dict[str, Any]] = []
        fallback: list[dict[str, Any]] = []
        for dependency in dependencies:
            if not isinstance(dependency, dict):
                continue
            digest = dependency.get("digest")
            if not isinstance(digest, dict):
                continue
            value = digest.get("gitCommit") or digest.get("sha1")
            if not isinstance(value, str):
                continue
            dep_repo, _ = _repo_and_ref_from_uri(
                dependency.get("uri") if isinstance(dependency.get("uri"), str) else None
            )
            record = {"commit": value, "repository": dep_repo}
            (preferred if repository and dep_repo == repository else fallback).append(record)
        selected = (preferred or fallback)
        if selected:
            commit = selected[0]["commit"]

    builder_obj = run_details.get("builder")
    metadata = run_details.get("metadata")
    builder_id = builder_obj.get("id") if isinstance(builder_obj, dict) and isinstance(builder_obj.get("id"), str) else None
    invocation_id = metadata.get("invocationId") if isinstance(metadata, dict) and isinstance(metadata.get("invocationId"), str) else None
    subject_name, subject_sha512 = _subject(statement)
    return ProvenanceClaims(
        statement_type=str(statement.get("_type", "")),
        predicate_type=SLSA_V1,
        subject_name=subject_name,
        subject_sha512=subject_sha512,
        repository=repository,
        workflow=workflow_path,
        commit_sha=commit.lower() if isinstance(commit, str) else None,
        ref=ref,
        builder_id=builder_id,
        invocation_id=invocation_id,
    )


def _claims_v02(statement: dict[str, Any]) -> ProvenanceClaims:
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        raise NpmVerificationError("SLSA v0.2 provenance did not include a predicate object")
    builder = predicate.get("builder")
    invocation = predicate.get("invocation")
    metadata = predicate.get("metadata")
    config_source = invocation.get("configSource") if isinstance(invocation, dict) else None
    if not isinstance(config_source, dict):
        raise NpmVerificationError("SLSA v0.2 provenance omitted invocation.configSource")

    uri = config_source.get("uri") if isinstance(config_source.get("uri"), str) else None
    repository, ref = _repo_and_ref_from_uri(uri)
    digest = config_source.get("digest")
    commit = None
    if isinstance(digest, dict):
        raw_commit = digest.get("sha1") or digest.get("gitCommit")
        commit = raw_commit.lower() if isinstance(raw_commit, str) else None
    workflow = config_source.get("entryPoint") if isinstance(config_source.get("entryPoint"), str) else None
    builder_id = builder.get("id") if isinstance(builder, dict) and isinstance(builder.get("id"), str) else None
    invocation_id = None
    if isinstance(metadata, dict):
        raw_invocation = metadata.get("buildInvocationId") or metadata.get("invocationId")
        invocation_id = raw_invocation if isinstance(raw_invocation, str) else None
    subject_name, subject_sha512 = _subject(statement)
    return ProvenanceClaims(
        statement_type=str(statement.get("_type", "")),
        predicate_type=SLSA_V02,
        subject_name=subject_name,
        subject_sha512=subject_sha512,
        repository=repository,
        workflow=workflow,
        commit_sha=commit,
        ref=ref,
        builder_id=builder_id,
        invocation_id=invocation_id,
    )


def _extract_claims(
    records: list[dict[str, Any]],
) -> tuple[ProvenanceClaims, tuple[str, ...], tuple[str, ...]]:
    entries: list[dict[str, Any]] = []
    for record in records:
        bundles = record.get("attestationBundles")
        if not isinstance(bundles, list):
            continue
        entries.extend(item for item in bundles if isinstance(item, dict))
    if len(entries) > MAX_ATTESTATION_BUNDLES:
        raise NpmVerificationError("verified attestation count exceeded the safety limit")

    verified_types: list[str] = []
    publish_types: list[str] = []
    provenance: list[ProvenanceClaims] = []
    for entry in entries:
        predicate_hint = entry.get("predicateType")
        statement = _decode_statement(entry)
        predicate_type = statement.get("predicateType")
        if not isinstance(predicate_type, str):
            predicate_type = predicate_hint if isinstance(predicate_hint, str) else None
        if not predicate_type:
            continue
        verified_types.append(predicate_type)
        if predicate_type in {NPM_PUBLISH_V01, IN_TOTO_RELEASE_V01}:
            publish_types.append(predicate_type)
        if predicate_type == SLSA_V1:
            provenance.append(_claims_v1(statement))
        elif predicate_type == SLSA_V02:
            provenance.append(_claims_v02(statement))

    if not provenance:
        raise NpmVerificationError("no supported SLSA provenance statement was present in verified bundles")

    unique = {
        (
            item.repository,
            item.workflow,
            item.commit_sha,
            item.ref,
            item.builder_id,
        )
        for item in provenance
    }
    if len(unique) > 1:
        raise NpmVerificationError("verified provenance statements contained conflicting source identities")

    # Prefer current SLSA v1 when both compatible v0.2 and v1 statements exist.
    selected = next((item for item in provenance if item.predicate_type == SLSA_V1), provenance[0])
    return selected, tuple(sorted(set(verified_types))), tuple(sorted(set(publish_types)))
