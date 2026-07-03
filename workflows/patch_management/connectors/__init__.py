"""
Connector registry for the patch_management workflow.

To add a new platform: add one entry here — no other files change.
"""

from workflows.patch_management.connectors.azure_devops import AzureDevOpsConnector
from workflows.patch_management.connectors.base import BasePlatformConnector
from workflows.patch_management.connectors.github import GitHubConnector

CONNECTOR_REGISTRY: dict[str, type[BasePlatformConnector]] = {
    "github": GitHubConnector,
    "azure_devops": AzureDevOpsConnector,
    # Future platforms (not yet implemented):
    # "gitlab": GitLabConnector,
    # "bitbucket": BitbucketConnector,
}
