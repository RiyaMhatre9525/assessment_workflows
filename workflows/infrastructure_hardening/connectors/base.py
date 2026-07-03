"""
workflows/infrastructure_hardening/connectors/base.py

Shared abstractions and data classes for infrastructure_hardening connectors.

Two connector families exist for this workflow:
  - VCS connectors   (GitHub, Azure DevOps)  -> BaseVCSConnector
  - Cloud connectors (Azure, future AWS/GCP) -> BaseCloudConnector

Both inherit BasePlatformConnector so they share credential handling,
API-call logging, and the health_check()/collect() contract required by
WORKFLOW_TEMPLATE_CONTEXT.md Pattern 6. Both connector types write into
the SAME shared PlatformData object so downstream LLM nodes see one
unified picture of the environment (VCS evidence + cloud evidence).
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Shared evidence dataclasses (grouped by assessment concern, not by level,
# since several levels reference the same underlying signal e.g. MFA).
# ---------------------------------------------------------------------------

@dataclass
class AccessControlInfo:
    admin_count: int = 0
    mfa_enforced_admin_pct: float = 0.0
    mfa_enforced_all_pct: float = 0.0
    privilege_review_documented: bool = False
    rbac_enabled: bool = False
    dedicated_security_account: bool = False


@dataclass
class EncryptionInfo:
    edge_https_enforced: bool = False
    internal_mtls_enabled: bool = False
    encryption_at_rest_enabled: bool = False
    disk_encryption_type: str = ""


@dataclass
class NetworkInfo:
    egress_filtering_enabled: bool = False
    network_isolation_enabled: bool = False
    waf_mode: str = ""            # "", "monitoring", "medium", "advanced"
    waf_custom_rule_count: int = 0
    waf_ml_detection: bool = False


@dataclass
class InfrastructureInfo:
    virtualized_environments: bool = False
    immutable_infrastructure: bool = False
    iac_managed: bool = False
    iac_tool: str = ""
    resource_limits_enforced: bool = False
    chaos_engineering_enabled: bool = False
    cis_bench_level: int = 0      # 0 = none, 1-2 = baseline, 2-3 = advanced
    syscall_restrictions_enabled: bool = False


@dataclass
class BackupInfo:
    automated_backups_enabled: bool = False
    backup_restore_tested: bool = False
    pre_deploy_backup: bool = False


@dataclass
class EnvironmentInfo:
    test_env_separate: bool = False
    prod_parity_local_dev: bool = False
    anonymized_test_data: bool = False


@dataclass
class PlatformData:
    """Aggregated evidence collected from BOTH the VCS connector and the
    cloud connector for a single assessment run."""
    vcs_type: str = ""
    cloud_type: str = ""
    repository: str = ""

    access_control: AccessControlInfo = field(default_factory=AccessControlInfo)
    encryption: EncryptionInfo = field(default_factory=EncryptionInfo)
    network: NetworkInfo = field(default_factory=NetworkInfo)
    infrastructure: InfrastructureInfo = field(default_factory=InfrastructureInfo)
    backup: BackupInfo = field(default_factory=BackupInfo)
    environment: EnvironmentInfo = field(default_factory=EnvironmentInfo)

    raw_metadata: dict = field(default_factory=dict)
    api_call_log: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Base connector contract
# ---------------------------------------------------------------------------

class BasePlatformConnector(ABC):
    """Shared base for both VCS and Cloud connectors."""

    def __init__(self, credentials: dict) -> None:
        self.credentials = credentials
        self._api_call_log: list[str] = []

    def _log(self, message: str) -> None:
        self._api_call_log.append(message)

    @abstractmethod
    async def health_check(self) -> bool:
        """Cheap credential/connectivity check before attempting collect()."""

    @abstractmethod
    async def collect(self, repository: str, platform_data: PlatformData) -> PlatformData:
        """Populate and return the shared PlatformData object with this
        connector's evidence. Must not overwrite fields owned by the
        other connector family."""


class BaseVCSConnector(BasePlatformConnector):
    """Version control connectors (GitHub, Azure DevOps, ...)."""


class BaseCloudConnector(BasePlatformConnector):
    """Cloud platform connectors (Azure, AWS, GCP, ...)."""
