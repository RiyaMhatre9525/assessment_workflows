"""
AzureDevOpsConnector — VCS connector for monitoring_domain.

Searches an Azure Repos repository for monitoring-as-code configuration
files and pipeline definitions that reference monitoring/metrics tooling.
Returns raw file content (never pre-flattened booleans).
"""

import base64

import httpx

from core.logger import get_logger
from .base import BasePlatformConnector, MonitoringConfigFile, VCSMonitoringData

logger = get_logger(__name__)

ADO_API_VERSION = "7.1"

MONITORING_CONFIG_CANDIDATES = [
    "prometheus.yml",
    "prometheus.yaml",
    "alertmanager.yml",
    "alertmanager.yaml",
    "datadog.yaml",
    "monitoring/config.yaml",
    "observability/config.yaml",
]

PIPELINE_FILE_CANDIDATES = [
    "azure-pipelines.yml",
    "azure-pipelines.yaml",
]


class AzureDevOpsConnector(BasePlatformConnector):
    def __init__(self, credentials: dict) -> None:
        super().__init__(credentials)
        self.organization = credentials.get("organization", "")
        self.project = credentials.get("project", "")
        self.pat = credentials.get("token", "")

    def _base_url(self, repository: str) -> str:
        return f"https://dev.azure.com/{self.organization}/{self.project}/_apis/git/repositories/{repository}"

    def _headers(self) -> dict:
        encoded = base64.b64encode(f":{self.pat}".encode()).decode()
        return {"Authorization": f"Basic {encoded}"}

    async def health_check(self) -> bool:
        url = f"https://dev.azure.com/{self.organization}/_apis/projects?api-version={ADO_API_VERSION}"
        self._log(f"GET {url}")
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(url, headers=self._headers())
                return resp.status_code == 200
        except Exception as exc:
            logger.error("Azure DevOps health_check failed: %s", exc, exc_info=True)
            return False

    async def _fetch_file(self, client: httpx.AsyncClient, repository: str, path: str) -> str:
        url = f"{self._base_url(repository)}/items"
        params = {"path": f"/{path}", "api-version": ADO_API_VERSION, "includeContent": "true"}
        self._log(f"GET {url}?path=/{path}")
        try:
            resp = await client.get(url, headers=self._headers(), params=params)
            if resp.status_code != 200:
                return ""
            return resp.text
        except Exception as exc:
            logger.warning("Azure DevOps file fetch failed for %s: %s", path, exc)
            return ""

    async def collect(self, repository: str) -> VCSMonitoringData:
        data = VCSMonitoringData(platform_type="azure_devops", repository=repository)

        async with httpx.AsyncClient(timeout=20) as client:
            for candidate in MONITORING_CONFIG_CANDIDATES:
                content = await self._fetch_file(client, repository, candidate)
                if content:
                    data.monitoring_config_files.append(
                        MonitoringConfigFile(name=candidate.split("/")[-1], path=candidate, raw_content=content)
                    )

            for candidate in PIPELINE_FILE_CANDIDATES:
                content = await self._fetch_file(client, repository, candidate)
                if content and any(
                    kw in content.lower()
                    for kw in ["prometheus", "grafana", "datadog", "monitor", "metrics", "alert"]
                ):
                    data.ci_monitoring_steps.append(
                        MonitoringConfigFile(name=candidate, path=candidate, raw_content=content)
                    )

        data.api_call_log = list(self._api_call_log)
        return data
