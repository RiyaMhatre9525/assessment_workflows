"""
Azure DevOps platform connector.

Queries the Azure DevOps REST API to collect pipeline and security data.

Expected credentials dict keys:
    pat           (str) – Personal Access Token with read access
    organization  (str) – Azure DevOps organization name
    project       (str) – Project name (optional; can be parsed from repository)
"""

from __future__ import annotations

import base64
import re
from typing import Any

import httpx

from core.logger import get_logger
from workflows.build_domain.connectors.base import (
    ArtifactInfo,
    ArtifactSigningInfo,
    BasePlatformConnector,
    CommitSigningInfo,
    PipelineInfo,
    PlatformData,
)

logger = get_logger(__name__)

_SIGNING_TOOLS = ("docker_content_trust", "in-toto", "cosign", "sigstore", "notation")


class AzureDevOpsConnector(BasePlatformConnector):
    """
    Connector for Azure DevOps (Pipelines + Repos + Artifacts).

    Uses the Azure DevOps REST API 7.1.  Authentication is via Basic auth
    with a PAT encoded as base64(:<pat>).

    credentials keys:
        pat           (required) – Azure DevOps PAT
        organization  (required) – ADO org name (e.g. "mycompany")
        project       (optional) – Project; derived from `repository` if omitted
    """

    def __init__(self, credentials: dict[str, Any]) -> None:
        super().__init__(credentials)
        pat = credentials.get("pat", "")
        encoded = base64.b64encode(f":{pat}".encode()).decode()
        self._org = credentials.get("organization", "")
        self._project = credentials.get("project", "")
        self._headers = {
            "Authorization": f"Basic {encoded}",
            "Content-Type": "application/json",
        }
        self._base = f"https://dev.azure.com/{self._org}"

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def health_check(self) -> bool:
        """Validate credentials by listing projects."""
        url = f"{self._base}/_apis/projects?api-version=7.1"
        self._log(f"GET {url}")
        try:
            async with httpx.AsyncClient(headers=self._headers, timeout=10) as client:
                resp = await client.get(url)
                ok = resp.status_code == 200
                logger.info("AzureDevOps health check: %s", "OK" if ok else f"FAILED ({resp.status_code})")
                return ok
        except Exception as exc:
            logger.error("AzureDevOps health check error: %s", exc)
            return False

    async def collect(self, repository: str, branch: str = "") -> PlatformData:
        """
        Collect all assessment data.

        Args:
            repository: Format "project/repo" or just "repo" (project from credentials).
            branch: Optional branch name to analyze.
        """
        parts = repository.split("/", 1)
        project = parts[0] if len(parts) == 2 else (self._project or repository)
        repo_name = parts[1] if len(parts) == 2 else repository

        logger.info("AzureDevOpsConnector.collect: org=%s project=%s repo=%s (branch: %s)",
                    self._org, project, repo_name, branch)

        data = PlatformData(platform_type="azure_devops", repository=repository)

        async with httpx.AsyncClient(headers=self._headers, timeout=30) as client:
            data.pipelines = await self._collect_pipelines(client, project, branch)
            data.artifacts = await self._collect_artifacts(client, project)
            data.commit_signing = await self._collect_commit_signing(client, project, repo_name, branch)
            data.artifact_signing = self._detect_artifact_signing(data.pipelines)

        data.api_call_log = list(self._api_call_log)
        return data

    # ------------------------------------------------------------------
    # Level 1 – pipeline discovery
    # ------------------------------------------------------------------

    async def _collect_pipelines(
        self, client: httpx.AsyncClient, project: str, branch: str = ""
    ) -> list[PipelineInfo]:
        """List Azure Pipelines and fetch their YAML definitions."""
        url = f"{self._base}/{project}/_apis/pipelines?api-version=7.1"
        self._log(f"GET {url}")

        pipelines: list[PipelineInfo] = []
        try:
            resp = await client.get(url)
            if resp.status_code != 200:
                logger.warning("No pipelines found (HTTP %s)", resp.status_code)
                return []

            for item in resp.json().get("value", []):
                pipeline = await self._fetch_pipeline_yaml(client, project, item, branch)
                pipelines.append(pipeline)
        except Exception as exc:
            logger.error("Error fetching pipelines: %s", exc)

        return pipelines

    async def _fetch_pipeline_yaml(
        self, client: httpx.AsyncClient, project: str, item: dict, branch: str = ""
    ) -> PipelineInfo:
        """Fetch the YAML definition of a single pipeline."""
        pid = item.get("id")
        name = item.get("name", "unknown")
        url = f"{self._base}/{project}/_apis/pipelines/{pid}?api-version=7.1"
        self._log(f"GET {url}")

        pipeline = PipelineInfo(name=name, path=f"pipeline/{pid}")
        try:
            resp = await client.get(url)
            if resp.status_code == 200:
                config = resp.json().get("configuration", {})
                yaml_path = config.get("path", "")
                repo_info = config.get("repository", {})
                pipeline.path = yaml_path or pipeline.path

                # Attempt to download the YAML file
                if yaml_path and repo_info:
                    raw = await self._download_file(client, project, repo_info, yaml_path, branch)
                    if raw:
                        pipeline.raw_content = raw
                        pipeline.has_build_job = bool(
                            re.search(r"\b(build|compile|dotnet build|mvn|gradle)\b", raw, re.I)
                        )
                        pipeline.has_test_job = bool(
                            re.search(r"\b(test|pytest|jest|NUnit|xUnit|MSTest)\b", raw, re.I)
                        )
                        pipeline.has_security_scan_job = bool(
                            re.search(
                                r"\b(trivy|snyk|sonarqube|whitesource|mend|checkov|bandit|semgrep)\b",
                                raw, re.I,
                            )
                        )
        except Exception as exc:
            logger.error("Error fetching pipeline %s: %s", name, exc)

        return pipeline

    async def _download_file(
        self,
        client: httpx.AsyncClient,
        project: str,
        repo_info: dict,
        path: str,
        branch: str = "",
    ) -> str:
        """Download a file from Azure Repos."""
        repo_id = repo_info.get("id", "")
        if not repo_id:
            return ""
        url = (
            f"{self._base}/{project}/_apis/git/repositories/{repo_id}/items"
            f"?path={path}&api-version=7.1"
        )
        if branch:
            url += f"&versionDescriptor.version={branch}"
        self._log(f"GET {url}")
        try:
            resp = await client.get(url)
            if resp.status_code == 200:
                return resp.text
        except Exception as exc:
            logger.error("Error downloading file %s: %s", path, exc)
        return ""

    # ------------------------------------------------------------------
    # Level 2 – artifact / SBOM
    # ------------------------------------------------------------------

    async def _collect_artifacts(
        self, client: httpx.AsyncClient, project: str
    ) -> list[ArtifactInfo]:
        """List Azure Artifacts feeds and check for container packages."""
        url = f"{self._base}/{project}/_apis/artifacts/feeds?api-version=7.1"
        self._log(f"GET {url}")

        artifacts: list[ArtifactInfo] = []
        try:
            resp = await client.get(url)
            if resp.status_code == 200:
                for feed in resp.json().get("value", [])[:5]:
                    feed_id = feed.get("id")
                    pkg_url = (
                        f"https://feeds.dev.azure.com/{self._org}/{project}"
                        f"/_apis/packaging/feeds/{feed_id}/packages?api-version=7.1"
                    )
                    self._log(f"GET {pkg_url}")
                    pkg_resp = await client.get(pkg_url)
                    if pkg_resp.status_code == 200:
                        for pkg in pkg_resp.json().get("value", [])[:5]:
                            artifact = ArtifactInfo(
                                name=pkg.get("name", "unknown"),
                                tag=pkg.get("version", "unknown"),
                                # ADO doesn't expose sha256 directly in the listing
                                digest="",
                                immutability_enforced=feed.get("immutabilityAllowed", False),
                            )
                            artifacts.append(artifact)
        except Exception as exc:
            logger.error("Error collecting artifacts: %s", exc)

        return artifacts

    # ------------------------------------------------------------------
    # Level 3 – commit signing
    # ------------------------------------------------------------------

    async def _collect_commit_signing(
        self,
        client: httpx.AsyncClient,
        project: str,
        repo_name: str,
        branch: str = "",
    ) -> CommitSigningInfo:
        """Check commit verification and branch policies in Azure Repos."""
        info = CommitSigningInfo()

        # List commits
        url = (
            f"{self._base}/{project}/_apis/git/repositories/{repo_name}"
            f"/commits?$top=20&api-version=7.1"
        )
        if branch:
            url += f"&searchCriteria.itemVersion.version={branch}"
        self._log(f"GET {url}")
        try:
            resp = await client.get(url)
            if resp.status_code == 200:
                commits = resp.json().get("value", [])
                info.total_commits_checked = len(commits)
                # Azure DevOps REST API does not expose GPG verification in the
                # commits listing; we note this as unsigned by default.
                info.unsigned_commits = len(commits)
        except Exception as exc:
            logger.error("Error fetching commits: %s", exc)

        # Check branch policies
        policy_url = (
            f"{self._base}/{project}/_apis/policy/configurations?api-version=7.1"
        )
        self._log(f"GET {policy_url}")
        try:
            resp = await client.get(policy_url)
            if resp.status_code == 200:
                policies = resp.json().get("value", [])
                if policies:
                    info.branch_protection_enforced = True
                # ADO doesn't have a native "require signed commits" policy like GitHub;
                # proxied through a comment requirement or status-check policy
                commit_author_policy = "fa4e907d-c16b-452d-8106-7ece0966d1ac"
                info.required_signed_commits_policy = any(
                    p.get("type", {}).get("id") == commit_author_policy
                    for p in policies
                )
        except Exception as exc:
            logger.error("Error fetching branch policies: %s", exc)

        return info

    # ------------------------------------------------------------------
    # Level 5 – artifact signing (derived from pipeline YAML)
    # ------------------------------------------------------------------

    def _detect_artifact_signing(self, pipelines: list[PipelineInfo]) -> ArtifactSigningInfo:
        """Search pipeline YAML for signing tool references."""
        info = ArtifactSigningInfo()
        combined = "\n".join(p.raw_content for p in pipelines)
        pattern = "|".join(re.escape(t) for t in _SIGNING_TOOLS)
        match = re.search(pattern, combined, re.I)
        if match:
            info.signing_tool_detected = match.group(0).lower()
            info.all_artifacts_signed = True
            info.signature_verification_in_deployment = bool(
                re.search(r"\b(verify|cosign verify|notation verify|in-toto-verify)\b", combined, re.I)
            )
        return info
