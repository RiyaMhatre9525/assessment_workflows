"""
Azure DevOps connector for the patch_management workflow.

Uses the Azure DevOps REST API (https://dev.azure.com) for SCM evidence, and
optionally the Azure Container Registry REST API for image lifecycle
evidence when registry credentials are supplied.

Expected credentials shape:
{
    "token": "<azure-devops-pat>",
    "organization": "myorg",
    "project": "myproject",
    "repository": "myrepo",
    # Optional, enables image lifecycle checks:
    "registry_name": "myregistry",
    "registry_access_token": "<acr-bearer-token>"
}
"""

import base64
import re

import httpx

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

AZURE_DEVOPS_API_BASE = "https://dev.azure.com"
API_VERSION = "7.1"
MINIMAL_BASE_IMAGE_PATTERNS = (
    r"distroless",
    r"alpine",
    r"chainguard",
    r"scratch",
)


class AzureDevOpsConnector(BasePlatformConnector):
    def __init__(self, credentials: dict) -> None:
        super().__init__(credentials)
        self.token = credentials.get("token", "")
        self.organization = credentials.get("organization", "")
        self.project = credentials.get("project", "")
        self.registry_name = credentials.get("registry_name", "")
        self.registry_access_token = credentials.get("registry_access_token", "")
        basic = base64.b64encode(f":{self.token}".encode()).decode()
        self._headers = {"Authorization": f"Basic {basic}"}

    def _base_url(self, repository: str) -> str:
        return f"{AZURE_DEVOPS_API_BASE}/{self.organization}/{self.project}/_apis/git/repositories/{repository}"

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

    async def collect(self, repository: str) -> PatchManagementPlatformData:
        data = PatchManagementPlatformData(platform_type="azure_devops", repository=repository)

        async with httpx.AsyncClient(timeout=20, headers=self._headers) as client:
            data.policy = await self._collect_policy(client, repository)
            data.dependency_automation = await self._collect_dependency_automation(client, repository)
            data.merge_automation = await self._collect_merge_automation(client, repository)
            data.nightly_build = await self._collect_nightly_build(client, repository)
            data.attack_surface = await self._collect_attack_surface(client, repository)
            data.deployment = await self._collect_deployment(client, repository)

        data.image_lifecycle = await self._collect_image_lifecycle()
        data.api_call_log = list(self._api_call_log)
        return data

    # ------------------------------------------------------------------ #
    # Internal collectors
    # ------------------------------------------------------------------ #

    async def _get_file_content(self, client: httpx.AsyncClient, repository: str, path: str) -> str | None:
        url = f"{self._base_url(repository)}/items?path={path}&api-version={API_VERSION}"
        self._log(f"GET {url}")
        try:
            resp = await client.get(url)
            if resp.status_code != 200:
                return None
            return resp.text
        except Exception as exc:
            logger.warning("Failed to fetch %s: %s", path, exc)
            return None

    async def _collect_policy(self, client: httpx.AsyncClient, repository: str) -> PolicyEvidence:
        evidence = PolicyEvidence()
        candidates = ["PATCH_POLICY.md", "docs/PATCH_POLICY.md", "README.md"]
        for candidate in candidates:
            content = await self._get_file_content(client, repository, candidate)
            if content:
                evidence.policy_document_found = True
                evidence.source = candidate
                evidence.mentions_frequency = bool(re.search(r"frequenc|cadence|monthly|weekly|quarterly", content, re.I))
                evidence.mentions_responsibilities = bool(re.search(r"responsib|owner|accountable", content, re.I))
                evidence.mentions_review_process = bool(re.search(r"review process|approval|sign[- ]?off", content, re.I))
                evidence.raw_excerpt = content[:300]
                break

        # Fall back to the project Wiki if no repo doc was found.
        if not evidence.policy_document_found:
            wiki_url = f"{AZURE_DEVOPS_API_BASE}/{self.organization}/{self.project}/_apis/wiki/wikis?api-version={API_VERSION}"
            self._log(f"GET {wiki_url}")
            try:
                resp = await client.get(wiki_url)
                if resp.status_code == 200 and resp.json().get("value"):
                    evidence.policy_document_found = True
                    evidence.source = "azure_devops_wiki"
            except Exception as exc:
                logger.warning("Failed to check wiki: %s", exc)
        return evidence

    async def _collect_dependency_automation(self, client: httpx.AsyncClient, repository: str) -> DependencyAutomationEvidence:
        evidence = DependencyAutomationEvidence()
        config = await self._get_file_content(client, repository, ".azure-pipelines/dependency-management.yml")
        if config:
            evidence.tool_detected = "azure_dependency_management"
            evidence.config_found = True

        url = f"{self._base_url(repository)}/pullrequests?searchCriteria.status=all&api-version={API_VERSION}"
        self._log(f"GET {url}")
        try:
            resp = await client.get(url)
            if resp.status_code == 200:
                prs = resp.json().get("value", [])
                bot_prs = [
                    pr for pr in prs
                    if "dependabot" in pr.get("createdBy", {}).get("displayName", "").lower()
                    or "renovate" in pr.get("createdBy", {}).get("displayName", "").lower()
                ]
                evidence.automated_prs_open_count = sum(1 for pr in bot_prs if pr.get("status") == "active")
                evidence.automated_prs_merged_count = sum(1 for pr in bot_prs if pr.get("status") == "completed")
                evidence.sample_pr_titles = [pr.get("title", "") for pr in bot_prs[:5]]
                if bot_prs and not evidence.tool_detected:
                    evidence.tool_detected = "dependabot"
        except Exception as exc:
            logger.warning("Failed to fetch pull requests: %s", exc)
        return evidence

    async def _collect_merge_automation(self, client: httpx.AsyncClient, repository: str) -> MergeAutomationEvidence:
        evidence = MergeAutomationEvidence()
        url = f"{self._base_url(repository)}/pullrequests?searchCriteria.status=completed&api-version={API_VERSION}"
        self._log(f"GET {url}")
        try:
            resp = await client.get(url)
            if resp.status_code == 200:
                prs = resp.json().get("value", [])
                auto_complete_prs = [pr for pr in prs if pr.get("completionOptions")]
                if auto_complete_prs:
                    evidence.auto_merge_enabled = True
                    evidence.mechanism = "azure_auto_complete"
                    evidence.sample_auto_merged_prs = [pr.get("title", "") for pr in auto_complete_prs[:5]]
        except Exception as exc:
            logger.warning("Failed to inspect auto-complete: %s", exc)

        policy_url = f"{AZURE_DEVOPS_API_BASE}/{self.organization}/{self.project}/_apis/policy/configurations?api-version={API_VERSION}"
        self._log(f"GET {policy_url}")
        try:
            resp = await client.get(policy_url)
            if resp.status_code == 200 and resp.json().get("value"):
                evidence.validation_required = True
        except Exception as exc:
            logger.warning("Failed to inspect branch policies: %s", exc)
        return evidence

    async def _collect_nightly_build(self, client: httpx.AsyncClient, repository: str) -> NightlyBuildEvidence:
        evidence = NightlyBuildEvidence()
        url = f"{AZURE_DEVOPS_API_BASE}/{self.organization}/{self.project}/_apis/build/definitions?api-version={API_VERSION}"
        self._log(f"GET {url}")
        try:
            resp = await client.get(url)
            if resp.status_code != 200:
                return evidence
            for definition in resp.json().get("value", []):
                name = definition.get("name", "")
                if not re.search(r"image|base|nightly", name, re.I):
                    continue
                detail_url = f"{AZURE_DEVOPS_API_BASE}/{self.organization}/{self.project}/_apis/build/definitions/{definition['id']}?api-version={API_VERSION}"
                self._log(f"GET {detail_url}")
                detail_resp = await client.get(detail_url)
                if detail_resp.status_code != 200:
                    continue
                triggers = detail_resp.json().get("triggers", [])
                for trigger in triggers:
                    if trigger.get("triggerType") == "schedule":
                        schedules = trigger.get("schedules", [])
                        if schedules:
                            evidence.scheduled_pipeline_found = True
                            evidence.schedule_expression = str(schedules[0])
                            evidence.pipeline_name = name
                            break
                if evidence.scheduled_pipeline_found:
                    break
        except Exception as exc:
            logger.warning("Failed to inspect build definitions: %s", exc)
        return evidence

    async def _collect_attack_surface(self, client: httpx.AsyncClient, repository: str) -> AttackSurfaceEvidence:
        evidence = AttackSurfaceEvidence()
        content = await self._get_file_content(client, repository, "Dockerfile")
        if content is None:
            evidence.inspection_possible = False
            evidence.limitation_note = (
                "Dockerfile could not be retrieved via the Azure DevOps Items API; "
                "attack surface reduction could not be verified."
            )
            return evidence
        evidence.dockerfiles_inspected = 1
        from_lines = re.findall(r"^FROM\s+(\S+)", content, re.M | re.I)
        evidence.base_images_found.extend(from_lines)
        if any(re.search(pat, content, re.I) for pat in MINIMAL_BASE_IMAGE_PATTERNS):
            evidence.minimal_base_image_count += 1
        return evidence

    async def _collect_image_lifecycle(self) -> ImageLifecycleEvidence:
        evidence = ImageLifecycleEvidence()
        if not self.registry_name or not self.registry_access_token:
            evidence.registry_accessible = False
            evidence.limitation_note = (
                "No Azure Container Registry credentials supplied "
                "(registry_name / registry_access_token); image lifetime "
                "could not be verified."
            )
            return evidence

        url = f"https://{self.registry_name}.azurecr.io/acr/v1/_catalog"
        self._log(f"GET {url}")
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    url, headers={"Authorization": f"Bearer {self.registry_access_token}"}
                )
                if resp.status_code != 200:
                    evidence.limitation_note = f"Registry catalog request failed with status {resp.status_code}."
                    return evidence
                repositories = resp.json().get("repositories", [])
                evidence.registry_accessible = True
                evidence.images_checked = len(repositories)
                # Per-manifest age inspection is registry-specific and left as a
                # follow-up enhancement; report accessibility and count only.
                evidence.limitation_note = (
                    "Registry catalog accessible; per-image age/rebuild-frequency "
                    "inspection requires manifest-level API calls not yet implemented."
                )
        except Exception as exc:
            logger.warning("Failed to query container registry: %s", exc)
            evidence.limitation_note = f"Registry query failed: {exc}"
        return evidence

    async def _collect_deployment(self, client: httpx.AsyncClient, repository: str) -> DeploymentEvidence:
        evidence = DeploymentEvidence()
        url = f"{AZURE_DEVOPS_API_BASE}/{self.organization}/{self.project}/_apis/release/definitions?api-version={API_VERSION}"
        self._log(f"GET {url}")
        try:
            resp = await client.get(url)
            if resp.status_code != 200:
                return evidence
            definitions = resp.json().get("value", [])
            if definitions:
                evidence.deployment_pipeline_found = True
                evidence.pipeline_name = definitions[0].get("name", "")
                evidence.auto_triggered = True
                evidence.trigger_type = "on_release"
                evidence.deploys_dependency_updates = True
        except Exception as exc:
            logger.warning("Failed to inspect release definitions: %s", exc)
        return evidence
