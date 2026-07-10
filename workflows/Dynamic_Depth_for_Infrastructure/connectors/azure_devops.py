"""
Azure DevOps SCM connector for the Dynamic_Depth_for_Infrastructure workflow.

Scans Azure Pipelines YAML definitions for evidence of infrastructure
security tooling configured in CI/CD pipelines.

Expected credentials shape:
{
    "token": "<azure-devops-pat>",
    "organization": "myorg",
    "project": "myproject",
    "repository": "myrepo"
}
"""

import base64
import re

import httpx

from core.logger import get_logger
from workflows.Dynamic_Depth_for_Infrastructure.connectors.base import (
    BaseInfraSCMConnector,
    CloudConfigurationEvidence,
    ExposedServicesEvidence,
    InfrastructurePlatformData,
    LoadTestingEvidence,
    NetworkSegmentationEvidence,
    UnauthorizedInstallationEvidence,
    UnusedResourcesEvidence,
    WeakPasswordEvidence,
)
from workflows.Dynamic_Depth_for_Infrastructure.connectors.github import (
    CLOUD_CONFIG_KEYWORDS,
    CONTAINER_SECURITY_KEYWORDS,
    EXPOSED_SERVICES_KEYWORDS,
    LOAD_TEST_KEYWORDS,
    NETWORK_SEGMENTATION_KEYWORDS,
    UNUSED_RESOURCE_KEYWORDS,
    WEAK_PASSWORD_KEYWORDS,
)

logger = get_logger(__name__)

AZURE_DEVOPS_API_BASE = "https://dev.azure.com"
API_VERSION = "7.1"


class AzureDevOpsConnector(BaseInfraSCMConnector):
    def __init__(self, credentials: dict) -> None:
        super().__init__(credentials)
        self.token = credentials.get("token", "")
        self.organization = credentials.get("organization", "")
        self.project = credentials.get("project", "")
        basic = base64.b64encode(f":{self.token}".encode()).decode()
        self._headers = {"Authorization": f"Basic {basic}"}

    async def health_check(self) -> bool:
        url = f"{AZURE_DEVOPS_API_BASE}/{self.organization}/_apis/projects?api-version={API_VERSION}"
        self._log(f"GET {url}")
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(url, headers=self._headers)
                return resp.status_code == 200
        except Exception as exc:
            logger.error("Azure DevOps health_check failed: %s", exc, exc_info=True)
            return False

    async def collect_pipeline_evidence(self, repository: str) -> InfrastructurePlatformData:
        data = InfrastructurePlatformData(
            source_platform_type="azure_devops",
            repository=repository,
        )

        combined_text = await self._get_all_pipeline_content(repository)

        # Reuse same detection logic as GitHub connector
        from workflows.Dynamic_Depth_for_Infrastructure.connectors.github import GitHubConnector
        detector = GitHubConnector.__new__(GitHubConnector)
        data.exposed_services = detector._detect_exposed_services(combined_text)
        data.network_segmentation = detector._detect_network_segmentation(combined_text)
        data.cloud_configuration = detector._detect_cloud_configuration(combined_text)
        data.unauthorized_installation = detector._detect_unauthorized_installation(combined_text)
        data.weak_password = detector._detect_weak_password(combined_text)
        data.load_testing = detector._detect_load_testing(combined_text)
        data.unused_resources = detector._detect_unused_resources(combined_text)

        data.api_call_log = list(self._api_call_log)
        return data

    async def _get_all_pipeline_content(self, repository: str) -> str:
        combined = []
        url = (
            f"{AZURE_DEVOPS_API_BASE}/{self.organization}/{self.project}"
            f"/_apis/build/definitions?api-version={API_VERSION}"
        )
        self._log(f"GET {url}")
        try:
            async with httpx.AsyncClient(timeout=20, headers=self._headers) as client:
                resp = await client.get(url)
                if resp.status_code != 200:
                    return ""
                for definition in resp.json().get("value", []):
                    def_id = definition.get("id")
                    detail_url = (
                        f"{AZURE_DEVOPS_API_BASE}/{self.organization}/{self.project}"
                        f"/_apis/build/definitions/{def_id}?api-version={API_VERSION}"
                    )
                    self._log(f"GET {detail_url}")
                    detail_resp = await client.get(detail_url)
                    if detail_resp.status_code == 200:
                        combined.append(str(detail_resp.json()))

                # Also check repo files
                repo_url = (
                    f"{AZURE_DEVOPS_API_BASE}/{self.organization}/{self.project}"
                    f"/_apis/git/repositories/{repository}/items"
                    f"?recursionLevel=full&api-version={API_VERSION}"
                )
                self._log(f"GET {repo_url}")
                repo_resp = await client.get(repo_url)
                if repo_resp.status_code == 200:
                    combined.append(str(repo_resp.json()))
        except Exception as exc:
            logger.warning("Failed to collect Azure DevOps pipeline content: %s", exc)

        return "\n".join(combined).lower()
