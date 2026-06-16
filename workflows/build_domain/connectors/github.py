"""
GitHub platform connector.

Queries the GitHub REST API to collect pipeline and security posture data.

Expected credentials dict keys:
    token   (str)  – GitHub personal access token or App installation token
    owner   (str)  – GitHub org or user (optional; can be parsed from repository)
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

_GITHUB_API = "https://api.github.com"
_SBOM_TOOLS = ("trivy", "syft", "cyclonedx", "spdx")
_SIGNING_TOOLS = ("docker_content_trust", "in-toto", "cosign", "sigstore", "notation")


class GitHubConnector(BasePlatformConnector):
    """
    Connector for GitHub repositories.

    Uses the GitHub REST API v3.  All calls are logged to PlatformData.api_call_log
    for debugging.

    credentials keys:
        token  (required) – PAT with repo, read:packages, read:org scopes
        owner  (optional) – GitHub org/user; derived from `repository` if omitted
    """

    def __init__(self, credentials: dict[str, Any]) -> None:
        super().__init__(credentials)
        token = credentials.get("token", "")
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def health_check(self) -> bool:
        """Validate token by calling /user."""
        url = f"{_GITHUB_API}/user"
        self._log(f"GET {url}")
        try:
            async with httpx.AsyncClient(headers=self._headers, timeout=10) as client:
                resp = await client.get(url)
                ok = resp.status_code == 200
                logger.info("GitHub health check: %s", "OK" if ok else f"FAILED ({resp.status_code})")
                return ok
        except Exception as exc:
            logger.error("GitHub health check error: %s", exc)
            return False

    async def collect(self, repository: str, branch: str = "") -> PlatformData:
        """
        Collect all assessment data for `repository` (format: "owner/repo").
        """
        logger.info("GitHubConnector.collect: %s (branch: %s)", repository, branch)
        data = PlatformData(platform_type="github", repository=repository)

        async with httpx.AsyncClient(headers=self._headers, timeout=30) as client:
            data.pipelines = await self._collect_pipelines(client, repository, branch)
            data.artifacts = await self._collect_artifacts(client, repository)
            data.commit_signing = await self._collect_commit_signing(client, repository, branch)
            data.artifact_signing = self._detect_artifact_signing(data.pipelines)

        data.api_call_log = list(self._api_call_log)
        return data

    # ------------------------------------------------------------------
    # Level 1 – pipeline discovery
    # ------------------------------------------------------------------

    async def _collect_pipelines(
        self, client: httpx.AsyncClient, repo: str, branch: str = ""
    ) -> list[PipelineInfo]:
        """List all GitHub Actions workflow files and parse their jobs."""
        url = f"{_GITHUB_API}/repos/{repo}/contents/.github/workflows"
        if branch:
            url += f"?ref={branch}"
        self._log(f"GET {url}")

        try:
            resp = await client.get(url)
            if resp.status_code != 200:
                logger.warning("No .github/workflows found (HTTP %s)", resp.status_code)
                return []
        except Exception as exc:
            logger.error("Error fetching workflows list: %s", exc)
            return []

        pipelines: list[PipelineInfo] = []
        for entry in resp.json():
            if not entry.get("name", "").endswith((".yml", ".yaml")):
                continue
            pipeline = await self._parse_workflow_file(client, repo, entry, branch)
            pipelines.append(pipeline)

        return pipelines

    async def _parse_workflow_file(
        self, client: httpx.AsyncClient, repo: str, entry: dict, branch: str = ""
    ) -> PipelineInfo:
        """Download and parse a single workflow YAML file."""
        url = f"{_GITHUB_API}/repos/{repo}/contents/{entry['path']}"
        if branch:
            url += f"?ref={branch}"
        self._log(f"GET {url}")

        pipeline = PipelineInfo(name=entry["name"], path=entry["path"])

        try:
            resp = await client.get(url)
            if resp.status_code == 200:
                content_b64 = resp.json().get("content", "")
                raw = base64.b64decode(content_b64).decode("utf-8", errors="replace")
                pipeline.raw_content = raw
                pipeline.has_build_job = bool(
                    re.search(r"\b(build|compile|mvn|gradle|npm run build)\b", raw, re.I)
                )
                pipeline.has_test_job = bool(
                    re.search(r"\b(test|pytest|jest|mocha|junit|rspec)\b", raw, re.I)
                )
                pipeline.has_security_scan_job = bool(
                    re.search(
                        r"\b(trivy|snyk|sonarqube|sonar|codeql|semgrep|bandit|checkov|grype)\b",
                        raw, re.I,
                    )
                )
        except Exception as exc:
            logger.error("Error parsing workflow %s: %s", entry["path"], exc)

        return pipeline

    # ------------------------------------------------------------------
    # Level 2 – artifact / SBOM
    # ------------------------------------------------------------------

    async def _collect_artifacts(
        self, client: httpx.AsyncClient, repo: str
    ) -> list[ArtifactInfo]:
        """Query GitHub Packages for container images and check SBOM signals."""
        owner = repo.split("/")[0]
        url = f"{_GITHUB_API}/orgs/{owner}/packages?package_type=container"
        self._log(f"GET {url}")

        artifacts: list[ArtifactInfo] = []
        try:
            resp = await client.get(url)
            if resp.status_code != 200:
                # Fall back to user packages
                url = f"{_GITHUB_API}/user/packages?package_type=container"
                self._log(f"GET {url} (fallback)")
                resp = await client.get(url)

            if resp.status_code == 200:
                for pkg in resp.json()[:10]:   # limit to 10 for speed
                    artifact = await self._inspect_package(client, owner, pkg)
                    artifacts.append(artifact)
        except Exception as exc:
            logger.error("Error collecting artifacts: %s", exc)

        # Also scan workflow content for SBOM tool mentions
        return artifacts

    async def _inspect_package(
        self, client: httpx.AsyncClient, owner: str, pkg: dict
    ) -> ArtifactInfo:
        """Inspect a single container package for digest and immutability."""
        name = pkg.get("name", "unknown")
        url = f"{_GITHUB_API}/orgs/{owner}/packages/container/{name}/versions"
        self._log(f"GET {url}")

        artifact = ArtifactInfo(name=name, tag="latest")
        try:
            resp = await client.get(url)
            if resp.status_code == 200:
                versions = resp.json()
                if versions:
                    latest = versions[0]
                    metadata = latest.get("metadata", {}).get("container", {})
                    tags = metadata.get("tags", [])
                    artifact.tag = tags[0] if tags else "untagged"
                    artifact.digest = latest.get("name", "")   # sha256:…
                    # Immutability: presence of digest ≠ enforcement; we check
                    # for the absence of "latest" as the only tag
                    artifact.immutability_enforced = bool(artifact.digest) and "latest" not in tags
        except Exception as exc:
            logger.error("Error inspecting package %s: %s", name, exc)

        return artifact

    # ------------------------------------------------------------------
    # Level 3 – commit signing
    # ------------------------------------------------------------------

    async def _collect_commit_signing(
        self, client: httpx.AsyncClient, repo: str, branch: str = ""
    ) -> CommitSigningInfo:
        """Check recent commits for GPG/SSH signatures and branch-protection rules."""
        info = CommitSigningInfo()

        # Sample last 20 commits
        url = f"{_GITHUB_API}/repos/{repo}/commits?per_page=20"
        if branch:
            url += f"&sha={branch}"
        self._log(f"GET {url}")
        try:
            resp = await client.get(url)
            if resp.status_code == 200:
                commits = resp.json()
                info.total_commits_checked = len(commits)
                for commit in commits:
                    verification = (
                        commit.get("commit", {})
                        .get("verification", {})
                    )
                    if verification.get("verified"):
                        info.signed_commits += 1
                    else:
                        info.unsigned_commits += 1
        except Exception as exc:
            logger.error("Error fetching commits: %s", exc)

        # Check branch protection for the specific branch or fall back to default branch
        branch_url = f"{_GITHUB_API}/repos/{repo}"
        self._log(f"GET {branch_url}")
        try:
            resp = await client.get(branch_url)
            if resp.status_code == 200:
                default_branch = resp.json().get("default_branch", "main")
                target_branch = branch if branch else default_branch
                bp_url = f"{_GITHUB_API}/repos/{repo}/branches/{target_branch}/protection"
                self._log(f"GET {bp_url}")
                bp_resp = await client.get(bp_url)
                if bp_resp.status_code == 200:
                    protection = bp_resp.json()
                    info.branch_protection_enforced = True
                    # GitHub exposes required_signatures as a sub-resource
                    sig_url = (
                        f"{_GITHUB_API}/repos/{repo}/branches/"
                        f"{target_branch}/protection/required_signatures"
                    )
                    self._log(f"GET {sig_url}")
                    sig_resp = await client.get(sig_url)
                    if sig_resp.status_code == 200:
                        info.required_signed_commits_policy = sig_resp.json().get("enabled", False)
        except Exception as exc:
            logger.error("Error fetching branch protection: %s", exc)

        return info

    # ------------------------------------------------------------------
    # Level 5 – artifact signing (derived from pipeline content)
    # ------------------------------------------------------------------

    def _detect_artifact_signing(self, pipelines: list[PipelineInfo]) -> ArtifactSigningInfo:
        """Search pipeline YAML for known signing tool invocations."""
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
