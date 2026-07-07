"""
Shared connector ABC and dataclasses for the monitoring_domain workflow.

Follows the dual-registry pattern introduced in logging_domain: VCS platforms
(GitHub, Azure DevOps) and Cloud platforms (Azure, extensible to AWS/GCP) are
independent connector families with independent credential sets, but share
this one BasePlatformConnector ABC and logging convention.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


# ─────────────────────────────────────────────────────────────────────────
# VCS-side data classes (monitoring-as-code configuration found in a repo)
# ─────────────────────────────────────────────────────────────────────────
@dataclass
class MonitoringConfigFile:
    name: str
    path: str
    raw_content: str = ""


@dataclass
class VCSMonitoringData:
    platform_type: str
    repository: str
    monitoring_config_files: list[MonitoringConfigFile] = field(default_factory=list)
    ci_monitoring_steps: list[MonitoringConfigFile] = field(default_factory=list)
    raw_metadata: dict = field(default_factory=dict)
    api_call_log: list[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────
# Cloud-side data classes (live monitoring/alerting/cost configuration)
# ─────────────────────────────────────────────────────────────────────────
@dataclass
class CloudMonitoringData:
    platform_type: str
    subscription_id: str = ""
    metric_definitions: list[dict] = field(default_factory=list)
    metric_alert_rules: list[dict] = field(default_factory=list)
    cost_budgets: list[dict] = field(default_factory=list)
    diagnostic_settings: list[dict] = field(default_factory=list)
    action_groups: list[dict] = field(default_factory=list)
    dashboards: list[dict] = field(default_factory=list)
    security_metric_sources: list[dict] = field(default_factory=list)
    raw_metadata: dict = field(default_factory=dict)
    api_call_log: list[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────
# Shared connector ABC (Pattern 6)
# ─────────────────────────────────────────────────────────────────────────
class BasePlatformConnector(ABC):
    def __init__(self, credentials: dict) -> None:
        self.credentials = credentials
        self._api_call_log: list[str] = []

    def _log(self, message: str) -> None:
        self._api_call_log.append(message)

    @abstractmethod
    async def collect(self, repository: str) -> Any:
        """Collect raw monitoring configuration/metadata. Returns
        VCSMonitoringData for VCS connectors or CloudMonitoringData for
        Cloud connectors."""

    @abstractmethod
    async def health_check(self) -> bool:
        """Verify credentials/connectivity before collecting data."""
