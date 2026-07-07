"""
GitHubConnector — VCS connector for monitoring_domain.

Searches a GitHub repository for monitoring-as-code configuration files
(Prometheus, Grafana, Datadog, Alertmanager, exporters) and CI workflow
steps that reference monitoring/metrics tooling. Returns raw file content
(never pre-flattened booleans) so the LLM can reason over actual config.
"""

import httpx

from core.logger import get_logger
from .base import BasePlatformConnector, MonitoringConfigFile, VCSMonitoringData

logger = get_logger(__name__)

GITHUB_API_BASE = "https://api.github.com"

# Filenames/paths that commonly hold monitoring-as-code configuration.
MONITORING_CONFIG_CANDIDATES = [
    "prometheus.yml",
    "prometheus.yaml",
    "alertmanager.yml",
    "alertmanager.yaml",
    "grafana/dashboards",
    "datadog.yaml",
    "datadog-agent.yaml",
    ".datadog.yml",
    "monitoring/config.yaml",
    "observability/config.yaml",
]

# CI workflow files that may contain monitoring-related steps.
CI_WORKFLOW_DIR = ".github/workflows"


class GitHubConnector(BasePlatformConnector):
    def __init__(self, credentials: dict) -> None:
        super().__init__(credentials)
        self.token = credentials.get("token", "")

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
        }

    async def health_check(self) -> bool:
        url = f"{GITHUB_API_BASE}/user"
        self._log(f"GET {url}")
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(url, headers=self._headers())
                return resp.status_code == 200
        except Exception as exc:
            logger.error("GitHub health_check failed: %s", exc, exc_info=True)
            return False

    async def _fetch_file(self, client: httpx.AsyncClient, repository: str, path: str) -> str:
        url = f"{GITHUB_API_BASE}/repos/{repository}/contents/{path}"
        self._log(f"GET {url}")
        try:
            resp = await client.get(url, headers=self._headers())
            if resp.status_code != 200:
                return ""
            data = resp.json()
            if isinstance(data, dict) and data.get("encoding") == "base64":
                import base64
                return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
            return ""
        except Exception as exc:
            logger.warning("GitHub file fetch failed for %s: %s", path, exc)
            return ""

    async def _code_search(self, client: httpx.AsyncClient, repository: str, query: str) -> list[dict]:
        url = f"{GITHUB_API_BASE}/search/code"
        params = {"q": f"{query} repo:{repository}"}
        self._log(f"GET {url}?q={params['q']}")
        try:
            resp = await client.get(url, headers=self._headers(), params=params)
            if resp.status_code != 200:
                return []
            return resp.json().get("items", [])
        except Exception as exc:
            logger.warning("GitHub code search failed for '%s': %s", query, exc)
            return []

    async def collect(self, repository: str) -> VCSMonitoringData:
        data = VCSMonitoringData(platform_type="github", repository=repository)

        async with httpx.AsyncClient(timeout=20) as client:
            # 1. Direct-path monitoring config candidates
            for candidate in MONITORING_CONFIG_CANDIDATES:
                content = await self._fetch_file(client, repository, candidate)
                if content:
                    data.monitoring_config_files.append(
                        MonitoringConfigFile(name=candidate.split("/")[-1], path=candidate, raw_content=content)
                    )

            # 2. Broader code search for monitoring keywords not caught above
            for keyword in ["prometheus", "grafana", "datadog", "alertmanager", "cloudwatch"]:
                results = await self._code_search(client, repository, keyword)
                for item in results[:5]:
                    path = item.get("path", "")
                    if any(path == f.path for f in data.monitoring_config_files):
                        continue
                    content = await self._fetch_file(client, repository, path)
                    if content:
                        data.monitoring_config_files.append(
                            MonitoringConfigFile(name=path.split("/")[-1], path=path, raw_content=content)
                        )

            # 3. CI workflow files (look for monitoring-related steps)
            url = f"{GITHUB_API_BASE}/repos/{repository}/contents/{CI_WORKFLOW_DIR}"
            self._log(f"GET {url}")
            try:
                resp = await client.get(url, headers=self._headers())
                if resp.status_code == 200:
                    for entry in resp.json():
                        name = entry.get("name", "")
                        path = entry.get("path", "")
                        content = await self._fetch_file(client, repository, path)
                        if content and any(
                            kw in content.lower()
                            for kw in ["prometheus", "grafana", "datadog", "monitor", "metrics", "alert"]
                        ):
                            data.ci_monitoring_steps.append(
                                MonitoringConfigFile(name=name, path=path, raw_content=content)
                            )
            except Exception as exc:
                logger.warning("GitHub CI workflow listing failed: %s", exc)

        data.api_call_log = list(self._api_call_log)
        return data
