"""
Base platform connector interface.

All VCS / cloud connectors must implement this contract so the assessment
engine remains completely platform-agnostic.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Shared data structures returned by every connector
# ---------------------------------------------------------------------------

@dataclass
class PipelineInfo:
    """Lightweight representation of a CI/CD pipeline / workflow file."""
    name: str
    path: str                       # e.g. ".github/workflows/ci.yml"
    raw_content: str = ""           # YAML / Jenkinsfile text
    has_build_job: bool = False
    has_test_job: bool = False
    has_security_scan_job: bool = False


@dataclass
class ArtifactInfo:
    """Container / artefact metadata."""
    name: str
    tag: str
    digest: str = ""                # sha256:… hash (empty if unknown)
    immutability_enforced: bool = False
    sbom_detected: bool = False
    sbom_tool: str = ""             # e.g. "trivy", "syft"


@dataclass
class CommitSigningInfo:
    """Summary of commit-signing posture in a repository."""
    total_commits_checked: int = 0
    signed_commits: int = 0
    unsigned_commits: int = 0
    branch_protection_enforced: bool = False
    required_signed_commits_policy: bool = False


@dataclass
class ArtifactSigningInfo:
    """Digital signing information for build artefacts."""
    signing_tool_detected: str = ""   # e.g. "docker_content_trust", "in-toto"
    all_artifacts_signed: bool = False
    signature_verification_in_deployment: bool = False


@dataclass
class PlatformData:
    """Aggregated platform data collected by a connector."""
    platform_type: str
    repository: str
    pipelines: list[PipelineInfo] = field(default_factory=list)
    artifacts: list[ArtifactInfo] = field(default_factory=list)
    commit_signing: CommitSigningInfo = field(default_factory=CommitSigningInfo)
    artifact_signing: ArtifactSigningInfo = field(default_factory=ArtifactSigningInfo)
    raw_metadata: dict[str, Any] = field(default_factory=dict)
    api_call_log: list[str] = field(default_factory=list)       # every API call made


# ---------------------------------------------------------------------------
# Abstract connector
# ---------------------------------------------------------------------------

class BasePlatformConnector(ABC):
    """
    Abstract base class for all platform connectors.

    Subclasses authenticate against a specific platform (GitHub, Azure DevOps,
    etc.) and expose a uniform `collect()` method that returns PlatformData.
    The assessment nodes consume only PlatformData, so adding new connectors
    never touches assessment logic.
    """

    def __init__(self, credentials: dict[str, Any]) -> None:
        """
        Args:
            credentials: Platform-specific auth dict supplied by the API caller.
                         Expected keys vary per connector (see subclass docs).
        """
        self.credentials = credentials
        self._api_call_log: list[str] = []

    def _log(self, message: str) -> None:
        """Append a debug entry to the API call log."""
        self._api_call_log.append(message)

    @abstractmethod
    async def collect(self, repository: str) -> PlatformData:
        """
        Collect all platform data needed by the assessment engine.

        Args:
            repository: Identifier for the target repo (e.g. "owner/repo").

        Returns:
            PlatformData with all gathered information and the full API log.
        """

    @abstractmethod
    async def health_check(self) -> bool:
        """
        Verify credentials are valid and the platform is reachable.

        Returns:
            True if the connection is healthy, False otherwise.
        """
