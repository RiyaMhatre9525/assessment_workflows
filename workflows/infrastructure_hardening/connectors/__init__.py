"""
Connector registries for infrastructure_hardening.

Two registries live here — this is the ONLY place platform names are
mapped to connector classes:
  - VCS_CONNECTOR_REGISTRY: version control platforms (code-level signals)
  - CLOUD_CONNECTOR_REGISTRY: cloud platforms (runtime/infra-level signals)

To add a new platform: add one connector file + one registry entry here.
No other files change.
"""
from .base import BasePlatformConnector
from .github import GitHubConnector
from .azure_devops import AzureDevOpsConnector
from .azure import AzureCloudConnector

VCS_CONNECTOR_REGISTRY: dict[str, type[BasePlatformConnector]] = {
    "github": GitHubConnector,
    "azure_devops": AzureDevOpsConnector,
}

CLOUD_CONNECTOR_REGISTRY: dict[str, type[BasePlatformConnector]] = {
    "azure": AzureCloudConnector,
}

__all__ = [
    "BasePlatformConnector",
    "VCS_CONNECTOR_REGISTRY",
    "CLOUD_CONNECTOR_REGISTRY",
]
