from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class DeploymentPipelineInfo:
    name: str
    path: str
    raw_content: str = ""
    has_deployment_job: bool = False
    has_rollback_step: bool = False
    has_approval_gate: bool = False
    uses_iac: bool = False


@dataclass
class ArtifactInventoryInfo:
    name: str
    artifact_type: str  # container_image | package | vm_image
    tag: str = ""
    digest: str = ""
    source_verified: bool = False
    whitelist_approved: bool = False


@dataclass
class SecretsManagementInfo:
    tool_detected: str = ""       # e.g. "azure_key_vault", "hashicorp_vault", ""
    secrets_externalized: bool = False
    env_config_encrypted: bool = False


@dataclass
class DecommissioningInfo:
    process_documented: bool = False
    covers_containers: bool = False
    covers_kubernetes: bool = False


@dataclass
class DependencyTrackingInfo:
    tracking_tool_detected: str = ""
    vulnerabilities_tracked: bool = False
    artifact_dependency_map: bool = False


@dataclass
class ZeroDowntimeInfo:
    strategy: str = ""            # rolling | blue_green | canary | ""
    blue_green_detected: bool = False
    rolling_update_detected: bool = False


@dataclass
class FeatureToggleInfo:
    feature_flags_detected: bool = False
    env_var_toggles: bool = False


@dataclass
class DeploymentPlatformData:
    platform_type: str
    repository: str
    pipelines: list[DeploymentPipelineInfo] = field(default_factory=list)
    artifacts: list[ArtifactInventoryInfo] = field(default_factory=list)
    secrets: SecretsManagementInfo = field(default_factory=SecretsManagementInfo)
    decommissioning: DecommissioningInfo = field(default_factory=DecommissioningInfo)
    dependencies: DependencyTrackingInfo = field(default_factory=DependencyTrackingInfo)
    zero_downtime: ZeroDowntimeInfo = field(default_factory=ZeroDowntimeInfo)
    feature_toggles: FeatureToggleInfo = field(default_factory=FeatureToggleInfo)
    same_artifact_across_envs: bool = False
    raw_metadata: dict = field(default_factory=dict)
    api_call_log: list[str] = field(default_factory=list)


class BasePlatformConnector(ABC):
    def __init__(self, credentials: dict) -> None:
        self.credentials = credentials
        self._api_call_log: list[str] = []

    def _log(self, message: str) -> None:
        self._api_call_log.append(message)

    @abstractmethod
    async def health_check(self) -> bool: ...

    @abstractmethod
    async def collect(self, repository: str, branch: str) -> DeploymentPlatformData: ...
