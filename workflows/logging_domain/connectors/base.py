"""
Base connector classes and shared data structures for the logging_domain
workflow.

This workflow uses TWO connector families (dual registry pattern):
  - VCS connectors   (BaseVCSConnector)   → GitHub, Azure DevOps, ...
  - Cloud connectors (BaseCloudConnector) → Azure, (future: AWS, GCP, ...)

Each family has its own ABC, its own registry dict (connectors/__init__.py),
and is queried independently by collect_platform_data_node in nodes.py.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Shared data classes
# ---------------------------------------------------------------------------

@dataclass
class LogSourceInfo:
    """A single logging source detected in VCS config (pipeline/app config)."""
    name: str
    path: str
    raw_content: str = ""
    ships_to_centralized_system: bool = False
    logs_security_events: bool = False
    logs_login_logout: bool = False
    logs_user_lifecycle_events: bool = False


@dataclass
class VCSLoggingData:
    """Aggregated logging-relevant data collected from a VCS platform."""
    platform_type: str
    repository: str
    log_sources: list[LogSourceInfo] = field(default_factory=list)
    logging_config_files_found: list[str] = field(default_factory=list)
    correlation_ids_detected: bool = False
    pii_logging_policy_doc_found: bool = False
    raw_metadata: dict = field(default_factory=dict)
    api_call_log: list[str] = field(default_factory=list)


@dataclass
class CentralizedLogSystemInfo:
    """Info about the centralized logging/monitoring system in the cloud."""
    system_name: str = ""
    sources_ingesting: list[str] = field(default_factory=list)
    storage_encrypted: bool = False
    retention_days: int = 0
    integrity_protection_enabled: bool = False
    alerting_configured: bool = False


@dataclass
class SecurityEventLoggingInfo:
    login_logout_logged: bool = False
    user_created_logged: bool = False
    user_changed_logged: bool = False
    user_deleted_logged: bool = False
    correlation_across_sources: bool = False


@dataclass
class LogAnalysisInfo:
    keyword_search_supported: bool = False
    attack_detection_rules_configured: bool = False
    real_time_dashboard_available: bool = False
    gui_search_available: bool = False
    developer_access_to_app_logs: bool = False


@dataclass
class CloudLoggingData:
    """Aggregated logging-relevant data collected from a cloud platform."""
    platform_type: str
    centralized_log_system: CentralizedLogSystemInfo = field(
        default_factory=CentralizedLogSystemInfo
    )
    security_events: SecurityEventLoggingInfo = field(
        default_factory=SecurityEventLoggingInfo
    )
    log_analysis: LogAnalysisInfo = field(default_factory=LogAnalysisInfo)
    correlated_event_visualizations: list[str] = field(default_factory=list)
    raw_metadata: dict = field(default_factory=dict)
    api_call_log: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Base connector ABCs
# ---------------------------------------------------------------------------

class BaseVCSConnector(ABC):
    """Base class for all Version Control System connectors."""

    def __init__(self, credentials: dict) -> None:
        self.credentials = credentials
        self._api_call_log: list[str] = []

    def _log(self, message: str) -> None:
        self._api_call_log.append(message)

    @abstractmethod
    async def health_check(self) -> bool:
        """Return True if credentials/connectivity are valid."""

    @abstractmethod
    async def collect(self, repository: str) -> VCSLoggingData:
        """Collect logging-relevant configuration from the VCS repository."""


class BaseCloudConnector(ABC):
    """Base class for all Cloud Platform connectors."""

    def __init__(self, credentials: dict) -> None:
        self.credentials = credentials
        self._api_call_log: list[str] = []

    def _log(self, message: str) -> None:
        self._api_call_log.append(message)

    @abstractmethod
    async def health_check(self) -> bool:
        """Return True if credentials/connectivity are valid."""

    @abstractmethod
    async def collect(self, **kwargs: Any) -> CloudLoggingData:
        """Collect logging/monitoring configuration from the cloud platform."""
