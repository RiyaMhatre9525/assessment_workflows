"""
Connector registries for the Static_Depth_for_Infrastructure workflow.

To add a new provider:
  1. Create a new connector file implementing BaseSourceControlConnector or
     BaseCloudConnector.
  2. Add one entry to the matching registry below.
No other file changes are required.
"""

from workflows.Static_Depth_for_Infrastructure.connectors.azure_cloud import AzureCloudConnector
from workflows.Static_Depth_for_Infrastructure.connectors.azure_devops import AzureDevOpsConnector
from workflows.Static_Depth_for_Infrastructure.connectors.base import (
    BaseCloudConnector,
    BaseSourceControlConnector,
)
from workflows.Static_Depth_for_Infrastructure.connectors.github import GitHubConnector

SOURCE_CONTROL_CONNECTOR_REGISTRY: dict[str, type[BaseSourceControlConnector]] = {
    "azure_devops": AzureDevOpsConnector,
    "github": GitHubConnector,
    # Future: "gitlab": GitLabConnector, "bitbucket": BitbucketConnector,
    # "aws_codecommit": AwsCodeCommitConnector,
}

CLOUD_CONNECTOR_REGISTRY: dict[str, type[BaseCloudConnector]] = {
    "azure": AzureCloudConnector,
    # Future: "aws": AwsCloudConnector, "gcp": GcpCloudConnector,
    # "kubernetes": KubernetesConnector, "openshift": OpenShiftConnector,
}
