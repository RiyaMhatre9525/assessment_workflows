"""
Shared connector abstraction and data classes for application_hardening.

Two connector families exist, both inheriting BasePlatformConnector:
  - VCS connectors (github.py, azure_devops.py) — collect code-level signals
    (framework/encoding detection, parametrization, ASVS L1/L2/L3 code-side
    controls) from a repository.
  - Cloud connectors (azure.py) — collect runtime/infra-level signals
    (container non-root enforcement, HTTP security headers, ASVS
    infra-side controls) from a cloud environment/resource scope.

Both collect into the shared ApplicationSecurityData structure so LLM
level-nodes can reason over a single unified summary.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class FrameworkInfo:
    name: str = ""
    detected: bool = False
    safe_default_rendering: bool = False


@dataclass
class OutputEncodingInfo:
    frameworks_detected: list[FrameworkInfo] = field(default_factory=list)
    encoding_library_detected: str = ""
    csp_header_present: bool = False
    csp_policy: str = ""


@dataclass
class InputValidationInfo:
    parametrized_queries_detected: bool = False
    orm_tool_detected: str = ""
    stored_procedures_detected: bool = False
    raw_query_concatenation_found: bool = False


@dataclass
class AsvsComplianceInfo:
    asvs_level: int = 1  # 1, 2, or 3
    total_controls: int = 0
    controls_met: int = 0
    percentage: float = 0.0
    unmet_controls: list[str] = field(default_factory=list)


@dataclass
class ContainerSecurityInfo:
    images_scanned: int = 0
    non_root_enforced_count: int = 0
    root_images: list[str] = field(default_factory=list)
    enforcement_method: str = ""  # "image_build" | "runtime_flag" | "none"


@dataclass
class SecurityHeadersInfo:
    endpoints_checked: int = 0
    server_header_hidden: bool = False
    powered_by_header_removed: bool = False
    deployment_method: str = ""  # reverse_proxy | middleware | service_mesh | docker_image
    headers_present: dict[str, bool] = field(default_factory=dict)


@dataclass
class VcsSecurityData:
    """Code-level signals collected from a version control platform."""
    vcs_platform_type: str = ""
    repository: str = ""
    output_encoding: OutputEncodingInfo = field(default_factory=OutputEncodingInfo)
    input_validation: InputValidationInfo = field(default_factory=InputValidationInfo)
    asvs_l1_code: AsvsComplianceInfo = field(default_factory=AsvsComplianceInfo)
    asvs_l2_code: AsvsComplianceInfo = field(default_factory=AsvsComplianceInfo)
    asvs_l3_code: AsvsComplianceInfo = field(default_factory=AsvsComplianceInfo)
    raw_metadata: dict = field(default_factory=dict)
    api_call_log: list[str] = field(default_factory=list)


@dataclass
class CloudSecurityData:
    """Runtime/infra-level signals collected from a cloud platform."""
    cloud_platform_type: str = ""
    resource_scope: str = ""
    container_security: ContainerSecurityInfo = field(default_factory=ContainerSecurityInfo)
    security_headers: SecurityHeadersInfo = field(default_factory=SecurityHeadersInfo)
    asvs_l1_infra: AsvsComplianceInfo = field(default_factory=AsvsComplianceInfo)
    asvs_l2_infra: AsvsComplianceInfo = field(default_factory=AsvsComplianceInfo)
    asvs_l3_infra: AsvsComplianceInfo = field(default_factory=AsvsComplianceInfo)
    raw_metadata: dict = field(default_factory=dict)
    api_call_log: list[str] = field(default_factory=list)


@dataclass
class ApplicationSecurityData:
    """Unified view combining VCS and cloud signals for the LLM level-nodes."""
    vcs_data: VcsSecurityData = field(default_factory=VcsSecurityData)
    cloud_data: CloudSecurityData = field(default_factory=CloudSecurityData)

    @property
    def api_call_log(self) -> list[str]:
        return [*self.vcs_data.api_call_log, *self.cloud_data.api_call_log]


class BasePlatformConnector(ABC):
    """Base class for both VCS and cloud connectors."""

    def __init__(self, credentials: dict) -> None:
        self.credentials = credentials
        self._api_call_log: list[str] = []

    def _log(self, message: str) -> None:
        self._api_call_log.append(message)

    @abstractmethod
    async def collect(self, scope: str):
        """Collect security signals for the given scope (repository or
        resource scope) and return a VcsSecurityData or CloudSecurityData."""

    @abstractmethod
    async def health_check(self) -> bool: ...
