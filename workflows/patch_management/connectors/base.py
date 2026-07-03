"""
Base platform connector and evidence dataclasses for the patch_management
workflow.

Every concrete connector (github.py, azure_devops.py, ...) must inherit from
BasePlatformConnector and implement health_check() + collect(). Connectors
return a PatchManagementPlatformData instance which is the single source of
truth consumed by every level node — node code never talks to a platform API
directly.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


# --------------------------------------------------------------------------- #
# Evidence dataclasses
# --------------------------------------------------------------------------- #

@dataclass
class PolicyEvidence:
    """Evidence relating to Level 1 / Control 1 - Patch Policy."""
    policy_document_found: bool = False
    source: str = ""                 # e.g. "wiki", "README.md", "docs/PATCH_POLICY.md"
    mentions_frequency: bool = False
    mentions_responsibilities: bool = False
    mentions_review_process: bool = False
    raw_excerpt: str = ""            # short excerpt only, never full doc


@dataclass
class DependencyAutomationEvidence:
    """Evidence relating to Level 1 / Control 2 - Automated Pull Requests."""
    tool_detected: str = ""          # "dependabot" | "renovate" | "azure_dependency_management" | ""
    config_found: bool = False
    automated_prs_open_count: int = 0
    automated_prs_merged_count: int = 0
    vulnerability_alerts_enabled: bool = False
    sample_pr_titles: list = field(default_factory=list)


@dataclass
class MergeAutomationEvidence:
    """Evidence relating to Level 2 / Control 1 - Automated Merge."""
    auto_merge_enabled: bool = False
    mechanism: str = ""              # "github_auto_merge" | "azure_auto_complete" | ""
    validation_required: bool = False  # status checks / required reviewers gate auto-merge
    sample_auto_merged_prs: list = field(default_factory=list)


@dataclass
class NightlyBuildEvidence:
    """Evidence relating to Level 2 / Control 2 - Nightly Base Image Builds."""
    scheduled_pipeline_found: bool = False
    schedule_expression: str = ""    # e.g. cron string
    pipeline_name: str = ""
    last_run_status: str = ""


@dataclass
class AttackSurfaceEvidence:
    """Evidence relating to Level 2 / Control 3 - Reduction of Attack Surface."""
    dockerfiles_inspected: int = 0
    minimal_base_image_count: int = 0
    base_images_found: list = field(default_factory=list)
    inspection_possible: bool = True   # False if repo/Dockerfile access unavailable via API
    limitation_note: str = ""


@dataclass
class ImageLifecycleEvidence:
    """Evidence relating to Level 2 / Control 4 and Level 4 - Image lifetime."""
    registry_accessible: bool = False
    images_checked: int = 0
    max_image_age_days: Optional[float] = None
    avg_image_age_days: Optional[float] = None
    rebuild_frequency_days: Optional[float] = None
    third_party_images_tracked: int = 0
    limitation_note: str = ""


@dataclass
class DeploymentEvidence:
    """Evidence relating to Level 3 - Automated Deployment."""
    deployment_pipeline_found: bool = False
    pipeline_name: str = ""
    auto_triggered: bool = False
    trigger_type: str = ""           # "on_merge" | "on_release" | "manual" | ""
    deploys_dependency_updates: bool = False


@dataclass
class PatchManagementPlatformData:
    """
    Aggregate evidence bundle returned by connector.collect().
    This is the only object level nodes read from.
    """
    platform_type: str = ""
    repository: str = ""
    policy: PolicyEvidence = field(default_factory=PolicyEvidence)
    dependency_automation: DependencyAutomationEvidence = field(default_factory=DependencyAutomationEvidence)
    merge_automation: MergeAutomationEvidence = field(default_factory=MergeAutomationEvidence)
    nightly_build: NightlyBuildEvidence = field(default_factory=NightlyBuildEvidence)
    attack_surface: AttackSurfaceEvidence = field(default_factory=AttackSurfaceEvidence)
    image_lifecycle: ImageLifecycleEvidence = field(default_factory=ImageLifecycleEvidence)
    deployment: DeploymentEvidence = field(default_factory=DeploymentEvidence)
    raw_metadata: dict = field(default_factory=dict)
    api_call_log: list = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Base connector
# --------------------------------------------------------------------------- #

class BasePlatformConnector(ABC):
    """
    Abstract base for all patch_management platform connectors.

    Subclasses must never log credentials. Use self._log() to record every
    outbound API call for the api_call_log surfaced in the final result.
    """

    def __init__(self, credentials: dict) -> None:
        self.credentials = credentials
        self._api_call_log: list[str] = []

    def _log(self, message: str) -> None:
        self._api_call_log.append(message)

    @abstractmethod
    async def health_check(self) -> bool:
        """Return True if credentials are valid and the platform is reachable."""

    @abstractmethod
    async def collect(self, repository: str) -> PatchManagementPlatformData:
        """Gather all evidence required across every maturity level."""
