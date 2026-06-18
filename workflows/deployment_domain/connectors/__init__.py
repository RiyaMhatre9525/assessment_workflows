"""Connector registry — add a new platform by adding one entry here."""

from workflows.deployment_domain.connectors.github import GitHubConnector
from workflows.deployment_domain.connectors.azure_devops import AzureDevOpsConnector

CONNECTOR_REGISTRY = {
    "github": GitHubConnector,
    "azure_devops": AzureDevOpsConnector,
}
