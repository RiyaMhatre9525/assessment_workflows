"""
Connector registries for logging_domain.

Two registries live here — this is the ONLY place platform names are
mapped to connector classes:
  - VCS_CONNECTOR_REGISTRY: version control platforms (code-level signals)
  - CLOUD_CONNECTOR_REGISTRY: cloud platforms (runtime/infra-level signals)
"""
from .base import BaseVCSConnector, BaseCloudConnector
from .github import GitHubVCSConnector
from .azure_devops import AzureDevOpsVCSConnector
from .azure import AzureCloudConnector

VCS_CONNECTOR_REGISTRY: dict[str, type[BaseVCSConnector]] = {
    "github": GitHubVCSConnector,
    "azure_devops": AzureDevOpsVCSConnector,
}

CLOUD_CONNECTOR_REGISTRY: dict[str, type[BaseCloudConnector]] = {
    "azure": AzureCloudConnector,
}

__all__ = [
    "BaseVCSConnector",
    "BaseCloudConnector",
    "VCS_CONNECTOR_REGISTRY",
    "CLOUD_CONNECTOR_REGISTRY",
]
