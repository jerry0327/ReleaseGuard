from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .models import Finding
from .npm_attestations import ProvenanceClaims
from .npm_runtime import Runner


@dataclass(frozen=True)
class VerificationRequest:
    package: str
    version: str
    registry: str
    expected_repository: str
    expected_workflow: str
    expected_commit: str
    expected_ref: str | None
    expected_builder: str
    require_trusted_publisher: bool
    fail_on: str
    npm_executable: str
    timeout: float
    runner: Runner

    @property
    def target(self) -> str:
        return f"{self.package}@{self.version}"


@dataclass(frozen=True)
class RegistryMetadata:
    npm_version: str
    manifest: dict[str, Any]
    dist: dict[str, Any]
    attestations: dict[str, Any]
    publisher_id: str | None
    publisher_config_id: str | None
    findings: tuple[Finding, ...]


@dataclass(frozen=True)
class VerifiedArtifact:
    metadata: RegistryMetadata
    claims: ProvenanceClaims
    verified_attestation_types: tuple[str, ...]
    publish_attestation_types: tuple[str, ...]
