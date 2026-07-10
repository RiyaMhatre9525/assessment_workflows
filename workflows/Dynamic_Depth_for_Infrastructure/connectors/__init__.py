"""
Connector registry for the Dynamic_Depth_for_Infrastructure workflow.

To add a new SCM platform: add one entry to SCM_CONNECTOR_REGISTRY.
To add a new cloud provider: add one entry to CLOUD_CONNECTOR_REGISTRY.
No other files change.
"""

from workflows.Dynamic_Depth_for_Infrastructure.connectors.azure_cloud import AzureCloudConnector
from workflows.Dynamic_Depth_for_Infrastructure.connectors.azure_devops import AzureDevOpsConnector
from workflows.Dynamic_Depth_for_Infrastructure.connectors.base import (
    BaseInfraCloudConnector,
    BaseInfraSCMConnector,
)
from workflows.Dynamic_Depth_for_Infrastructure.connectors.github import GitHubConnector

SCM_CONNECTOR_REGISTRY: dict[str, type[BaseInfraSCMConnector]] = {
    "github": GitHubConnector,
    "azure_devops": AzureDevOpsConnector,
    # Future:
    # "gitlab": GitLabConnector,
    # "bitbucket": BitbucketConnector,
}

CLOUD_CONNECTOR_REGISTRY: dict[str, type[BaseInfraCloudConnector]] = {
    "azure": AzureCloudConnector,
    # Future:
    # "aws": AWSCloudConnector,
    # "gcp": GCPCloudConnector,
}
