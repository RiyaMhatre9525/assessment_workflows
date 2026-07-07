"""
Connector registries for monitoring_domain.

Dual-registry pattern (same as logging_domain): VCS platforms and Cloud
platforms are independent families with independent credential sets.
To add a new platform: add one new connector file + one new dict entry
in the appropriate registry below — no other files change.
"""

from .base import BasePlatformConnector, VCSMonitoringData, CloudMonitoringData
from .github import GitHubConnector
from .azure_devops import AzureDevOpsConnector
from .azure_cloud import AzureCloudConnector

VCS_CONNECTOR_REGISTRY: dict[str, type[BasePlatformConnector]] = {
    "github": GitHubConnector,
    "azure_devops": AzureDevOpsConnector,
}

CLOUD_CONNECTOR_REGISTRY: dict[str, type[BasePlatformConnector]] = {
    "azure": AzureCloudConnector,
    # extensible: "aws": AWSCloudConnector, "gcp": GCPCloudConnector
}

__all__ = [
    "BasePlatformConnector",
    "VCSMonitoringData",
    "CloudMonitoringData",
    "VCS_CONNECTOR_REGISTRY",
    "CLOUD_CONNECTOR_REGISTRY",
]
