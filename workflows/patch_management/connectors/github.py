"""
GitHub connector for the patch_management workflow.

Uses the GitHub REST API (https://api.github.com) to collect evidence for
every maturity level. Authentication is via a Personal Access Token supplied
in credentials["token"].

Expected credentials shape:
{
    "token": "<github-pat>",
    "repository": "org/repo"        # may also be passed at collect() call site
}
"""

import base64
import re

import httpx
from datetime import datetime, timezone

from core.logger import get_logger
from workflows.patch_management.connectors.base import (
    AttackSurfaceEvidence,
    BasePlatformConnector,
    DependencyAutomationEvidence,
    DeploymentEvidence,
    ImageLifecycleEvidence,
    MergeAutomationEvidence,
    NightlyBuildEvidence,
    PatchManagementPlatformData,
    PolicyEvidence,
)

logger = get_logger(__name__)

GITHUB_API_BASE = "https://api.github.com"
MINIMAL_BASE_IMAGE_PATTERNS = (
    r"distroless",
    r"alpine",
    r"chainguard",
    r"scratch",
)
POLICY_FILE_CANDIDATES = (
    "PATCH_POLICY.md",
    "docs/PATCH_POLICY.md",
    "SECURITY.md",
    ".github/SECURITY.md",
    "README.md",
)


class GitHubConnector(BasePlatformConnector):
    def __init__(self, credentials: dict) -> None:
        super().__init__(credentials)
        self.token = credentials.get("token", "")
        self._headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
        }

    async def health_check(self) -> bool:
        url = f"{GITHUB_API_BASE}/user"
        self._log(f"GET {url}")
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(url, headers=self._headers)
                return resp.status_code == 200
        except Exception as exc:
            logger.error("GitHub health_check failed: %s", exc, exc_info=True)
            return False

    async def collect(self, repository: str) -> PatchManagementPlatformData:
        data = PatchManagementPlatformData(platform_type="github", repository=repository)

        async with httpx.AsyncClient(timeout=20, headers=self._headers) as client:
            data.policy = await self._collect_policy(client, repository)
            data.dependency_automation = await self._collect_dependency_automation(client, repository)
            data.merge_automation = await self._collect_merge_automation(client, repository)
            data.nightly_build = await self._collect_nightly_build(client, repository)
            data.attack_surface = await self._collect_attack_surface(client, repository)
            data.image_lifecycle = await self._collect_image_lifecycle(client, repository)
            data.deployment = await self._collect_deployment(client, repository)

        data.api_call_log = list(self._api_call_log)
        return data

    # ------------------------------------------------------------------ #
    # Internal collectors
    # ------------------------------------------------------------------ #

    async def _get_file_content(self, client: httpx.AsyncClient, repository: str, path: str) -> str | None:
        url = f"{GITHUB_API_BASE}/repos/{repository}/contents/{path}"
        self._log(f"GET {url}")
        try:
            resp = await client.get(url)
            if resp.status_code != 200:
                return None
            payload = resp.json()
            content = payload.get("content", "")
            if not content:
                return None
            return base64.b64decode(content).decode("utf-8", errors="ignore")
        except Exception as exc:
            logger.warning("Failed to fetch %s: %s", path, exc)
            return None

    async def _collect_policy(self, client: httpx.AsyncClient, repository: str) -> PolicyEvidence:
        evidence = PolicyEvidence()
        for candidate in POLICY_FILE_CANDIDATES:
            content = await self._get_file_content(client, repository, candidate)
            if content:
                evidence.policy_document_found = True
                evidence.source = candidate
                evidence.mentions_frequency = bool(re.search(r"frequenc|cadence|monthly|weekly|quarterly", content, re.I))
                evidence.mentions_responsibilities = bool(re.search(r"responsib|owner|accountable", content, re.I))
                evidence.mentions_review_process = bool(re.search(r"review process|approval|sign[- ]?off", content, re.I))
                evidence.raw_excerpt = content[:300]
                break
        return evidence

    async def _collect_dependency_automation(self, client: httpx.AsyncClient, repository: str) -> DependencyAutomationEvidence:
        evidence = DependencyAutomationEvidence()
        dependabot_cfg = await self._get_file_content(client, repository, ".github/dependabot.yml")
        renovate_cfg = await self._get_file_content(client, repository, "renovate.json")
        if dependabot_cfg is None:
            dependabot_cfg = await self._get_file_content(client, repository, ".github/dependabot.yaml")
        if dependabot_cfg:
            evidence.tool_detected = "dependabot"
            evidence.config_found = True
        elif renovate_cfg:
            evidence.tool_detected = "renovate"
            evidence.config_found = True

        url = f"{GITHUB_API_BASE}/repos/{repository}/pulls?state=all&per_page=30"
        self._log(f"GET {url}")
        try:
            resp = await client.get(url)
            if resp.status_code == 200:
                prs = resp.json()
                bot_prs = [
                    pr for pr in prs
                    if pr.get("user", {}).get("login", "").lower() in ("dependabot[bot]", "renovate[bot]")
                ]
                evidence.automated_prs_open_count = sum(1 for pr in bot_prs if pr.get("state") == "open")
                evidence.automated_prs_merged_count = sum(1 for pr in bot_prs if pr.get("merged_at"))
                evidence.sample_pr_titles = [pr.get("title", "") for pr in bot_prs[:5]]
                if bot_prs and not evidence.tool_detected:
                    evidence.tool_detected = "dependabot"
        except Exception as exc:
            logger.warning("Failed to fetch pulls: %s", exc)

        alerts_url = f"{GITHUB_API_BASE}/repos/{repository}/vulnerability-alerts"
        self._log(f"GET {alerts_url}")
        try:
            resp = await client.get(alerts_url)
            evidence.vulnerability_alerts_enabled = resp.status_code == 204
        except Exception as exc:
            logger.warning("Failed to check vulnerability alerts: %s", exc)

        return evidence

    async def _collect_merge_automation(self, client: httpx.AsyncClient, repository: str) -> MergeAutomationEvidence:
        evidence = MergeAutomationEvidence()
        # Check for auto-merge workflow config file first
        auto_merge_workflow = await self._get_file_content(client, repository, ".github/workflows/auto-merge.yml")
        if auto_merge_workflow is None:
            auto_merge_workflow = await self._get_file_content(client, repository, ".github/workflows/automerge.yml")
        if auto_merge_workflow:
            evidence.auto_merge_enabled = True
            evidence.mechanism = "github_auto_merge"

        # Also check closed PRs for auto_merge field
        url = f"{GITHUB_API_BASE}/repos/{repository}/pulls?state=closed&per_page=30"
        self._log(f"GET {url}")
        try:
            resp = await client.get(url)
            if resp.status_code == 200:
                prs = resp.json()
                automerged = [pr for pr in prs if pr.get("auto_merge")]
                if automerged:
                    evidence.auto_merge_enabled = True
                    evidence.mechanism = "github_auto_merge"
                    evidence.sample_auto_merged_prs = [pr.get("title", "") for pr in automerged[:5]]
        except Exception as exc:
            logger.warning("Failed to inspect auto-merge: %s", exc)

        branch_url = f"{GITHUB_API_BASE}/repos/{repository}/branches/main/protection"
        self._log(f"GET {branch_url}")
        try:
            resp = await client.get(branch_url)
            if resp.status_code == 200:
                evidence.validation_required = True
        except Exception as exc:
            logger.warning("Failed to inspect branch protection: %s", exc)

        return evidence

    async def _collect_nightly_build(self, client: httpx.AsyncClient, repository: str) -> NightlyBuildEvidence:
        evidence = NightlyBuildEvidence()
        url = f"{GITHUB_API_BASE}/repos/{repository}/contents/.github/workflows"
        self._log(f"GET {url}")
        try:
            resp = await client.get(url)
            if resp.status_code != 200:
                return evidence
            for entry in resp.json():
                name = entry.get("name", "")
                content = await self._get_file_content(client, repository, f".github/workflows/{name}")
                if not content:
                    continue
                cron_match = re.search(r"cron:\s*['\"]([^'\"]+)['\"]", content)
                if cron_match and re.search(r"image|build|base", content, re.I):
                    evidence.scheduled_pipeline_found = True
                    evidence.schedule_expression = cron_match.group(1)
                    evidence.pipeline_name = name
                    break
        except Exception as exc:
            logger.warning("Failed to inspect workflows: %s", exc)
        return evidence

    async def _collect_attack_surface(self, client: httpx.AsyncClient, repository: str) -> AttackSurfaceEvidence:
        evidence = AttackSurfaceEvidence()
        dockerfile_paths = ["Dockerfile", "docker/Dockerfile", "app/Dockerfile"]
        for path in dockerfile_paths:
            content_str = await self._get_file_content(client, repository, path)
            if content_str:
                evidence.dockerfiles_inspected += 1
                from_lines = re.findall(r"^FROM\s+(\S+)", content_str, re.M | re.I)
                evidence.base_images_found.extend(from_lines)
                if any(re.search(pat, content_str, re.I) for pat in MINIMAL_BASE_IMAGE_PATTERNS):
                    evidence.minimal_base_image_count += 1
        if evidence.dockerfiles_inspected == 0:
            url = f"{GITHUB_API_BASE}/search/code?q=filename:Dockerfile+repo:{repository}"
            self._log(f"GET {url}")
            try:
                resp = await client.get(url)
                if resp.status_code != 200:
                    evidence.inspection_possible = False
                    evidence.limitation_note = "Dockerfile not found via direct path or search API."
                    return evidence
                items = resp.json().get("items", [])
                evidence.dockerfiles_inspected = len(items)
                for item in items[:10]:
                    ipath = item.get("path", "Dockerfile")
                    content_str = await self._get_file_content(client, repository, ipath)
                    if not content_str:
                        continue
                    from_lines = re.findall(r"^FROM\s+(\S+)", content_str, re.M | re.I)
                    evidence.base_images_found.extend(from_lines)
                    if any(re.search(pat, content_str, re.I) for pat in MINIMAL_BASE_IMAGE_PATTERNS):
                        evidence.minimal_base_image_count += 1
            except Exception as exc:
                logger.warning("Failed to inspect Dockerfiles: %s", exc)
                evidence.inspection_possible = False
                evidence.limitation_note = f"Dockerfile inspection failed: {exc}"
        return evidence

    async def _collect_image_lifecycle(self, client: httpx.AsyncClient, repository: str) -> ImageLifecycleEvidence:
        evidence = ImageLifecycleEvidence()
        repo_lower = repository.lower()
        url = f"{GITHUB_API_BASE}/user/packages/container/{repo_lower.split(chr(47))[1]}/versions"
        self._log(f"GET {url}")
        try:
            resp = await client.get(url)
            if resp.status_code != 200:
                evidence.registry_accessible = False
                evidence.limitation_note = f"GHCR package versions API returned {resp.status_code}."
                return evidence
            versions = resp.json()
            if not versions:
                evidence.registry_accessible = True
                evidence.limitation_note = "No image versions found in GHCR."
                return evidence
            evidence.registry_accessible = True
            evidence.images_checked = len(versions)
            ages = []
            for v in versions[:10]:
                updated = v.get("updated_at") or v.get("created_at")
                if updated:
                    dt = datetime.fromisoformat(updated.replace("Z", "+00:00"))
                    age_days = (datetime.now(timezone.utc) - dt).days
                    ages.append(age_days)
            if ages:
                evidence.max_image_age_days = float(max(ages))
                evidence.avg_image_age_days = float(sum(ages) / len(ages))
                evidence.rebuild_frequency_days = float(min(ages)) if len(ages) > 1 else None
        except Exception as exc:
            logger.warning("Failed to query GHCR: %s", exc)
            evidence.limitation_note = f"GHCR query failed: {exc}"
        return evidence

    async def _collect_deployment(self, client: httpx.AsyncClient, repository: str) -> DeploymentEvidence:
        evidence = DeploymentEvidence()
        url = f"{GITHUB_API_BASE}/repos/{repository}/contents/.github/workflows"
        self._log(f"GET {url}")
        try:
            resp = await client.get(url)
            if resp.status_code != 200:
                return evidence
            for entry in resp.json():
                name = entry.get("name", "")
                content = await self._get_file_content(client, repository, f".github/workflows/{name}")
                if not content:
                    continue
                if re.search(r"deploy", content, re.I):
                    evidence.deployment_pipeline_found = True
                    evidence.pipeline_name = name
                    if re.search(r"on:\s*\n?\s*(push|pull_request|release)", content, re.I):
                        evidence.auto_triggered = True
                        if re.search(r"release", content, re.I):
                            evidence.trigger_type = "on_release"
                        else:
                            evidence.trigger_type = "on_merge"
                    if re.search(r"dependabot|renovate|dependency", content, re.I):
                        evidence.deploys_dependency_updates = True
                    break
        except Exception as exc:
            logger.warning("Failed to inspect deployment workflows: %s", exc)
        return evidence
