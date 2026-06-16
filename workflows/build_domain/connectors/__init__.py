"""
Platform connectors for Pipeline Maturity Assessment.

Each connector implements the BasePlatformConnector interface, allowing
the assessment engine to query any platform without modifying core logic.

Registered connectors:
  - github   → GitHubConnector
  - azure_devops → AzureDevOpsConnector

Future connectors to add here (no changes to core assessment needed):
  - gitlab, bitbucket, aws_codecommit, gcp_cloudbuild, etc.
"""

from workflows.build_domain.connectors.base import BasePlatformConnector
from workflows.build_domain.connectors.github import GitHubConnector
from workflows.build_domain.connectors.azure_devops import AzureDevOpsConnector

CONNECTOR_REGISTRY: dict[str, type[BasePlatformConnector]] = {
    "github": GitHubConnector,
    "azure_devops": AzureDevOpsConnector,
}

__all__ = [
    "BasePlatformConnector",
    "GitHubConnector",
    "AzureDevOpsConnector",
    "CONNECTOR_REGISTRY",
]
