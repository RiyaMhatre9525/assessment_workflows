"""
GitHub connector for the Static_Depth_for_Infrastructure workflow.

Collects GitHub Actions workflow (YAML) definitions and a repository file
tree, then scans both for the same canonical signal set used by the Azure
DevOps connector so both providers feed the assessment nodes identical,
provider-agnostic evidence shapes.
"""

from __future__ import annotations

import base64

import httpx

from core.logger import get_logger
from workflows.Static_Depth_for_Infrastructure.connectors.azure_devops import _detect_signals
from workflows.Static_Depth_for_Infrastructure.connectors.base import (
    BaseSourceControlConnector,
    InfrastructureEvidence,
    PipelineDefinition,
)

logger = get_logger(__name__)

API_BASE = "https://api.github.com"
MAX_FILES = 500


class GitHubConnector(BaseSourceControlConnector):
    """
    Expected credentials:
        {
            "token": "<github-pat>"
        }
    repository is expected in "owner/repo" form.
    """

    def __init__(self, credentials: dict) -> None:
        super().__init__(credentials)
        self.token = credentials.get("token", "")
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
        }

    async def health_check(self) -> bool:
        url = f"{API_BASE}/user"
        self._log(f"GET {url}")
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(url, headers=self.headers)
                return response.status_code == 200
        except Exception as exc:
            logger.error("GitHub health_check failed: %s", exc)
            return False

    async def collect(self, repository: str) -> InfrastructureEvidence:
        pipeline_definitions = await self._collect_workflow_definitions(repository)
        repository_files = await self._collect_repository_files(repository)

        combined_text = "\n".join(p.raw_content for p in pipeline_definitions)
        signals = _detect_signals(combined_text, repository_files)

        return InfrastructureEvidence(
            platform_type="github",
            repository=repository,
            pipeline_definitions=pipeline_definitions,
            repository_files=repository_files,
            detected_signals=signals,
            raw_metadata={"repository": repository},
            api_call_log=self._api_call_log,
        )

    async def _collect_workflow_definitions(self, repository: str) -> list[PipelineDefinition]:
        definitions: list[PipelineDefinition] = []
        list_url = f"{API_BASE}/repos/{repository}/actions/workflows"
        self._log(f"GET {list_url}")

        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                response = await client.get(list_url, headers=self.headers)
                response.raise_for_status()
                workflows = response.json().get("workflows", [])

                for workflow in workflows:
                    name = workflow.get("name", "workflow")
                    path = workflow.get("path", "")

                    content_url = f"{API_BASE}/repos/{repository}/contents/{path}"
                    self._log(f"GET {content_url}")
                    content_resp = await client.get(content_url, headers=self.headers)

                    raw_content = ""
                    if content_resp.status_code == 200:
                        payload = content_resp.json()
                        encoded = payload.get("content", "")
                        try:
                            raw_content = base64.b64decode(encoded).decode("utf-8", errors="ignore")
                        except Exception:
                            raw_content = ""

                    definitions.append(PipelineDefinition(name=name, path=path, raw_content=raw_content))
        except Exception as exc:
            logger.error("GitHub workflow collection failed: %s", exc, exc_info=True)

        return definitions

    async def _collect_repository_files(self, repository: str) -> list[str]:
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                repo_url = f"{API_BASE}/repos/{repository}"
                self._log(f"GET {repo_url}")
                repo_resp = await client.get(repo_url, headers=self.headers)
                repo_resp.raise_for_status()
                default_branch = repo_resp.json().get("default_branch", "main")

                tree_url = f"{API_BASE}/repos/{repository}/git/trees/{default_branch}?recursive=1"
                self._log(f"GET {tree_url}")
                tree_resp = await client.get(tree_url, headers=self.headers)
                tree_resp.raise_for_status()
                tree = tree_resp.json().get("tree", [])
                paths = [item.get("path", "") for item in tree if item.get("type") == "blob"]
                return paths[:MAX_FILES]
        except Exception as exc:
            logger.error("GitHub repository file listing failed: %s", exc, exc_info=True)
            return []
