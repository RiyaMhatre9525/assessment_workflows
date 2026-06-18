import httpx
from core.logger import get_logger
from workflows.deployment_domain.connectors.base import (
    BasePlatformConnector,
    DeploymentPlatformData,
    DeploymentPipelineInfo,
    ArtifactInventoryInfo,
    SecretsManagementInfo,
    DecommissioningInfo,
    DependencyTrackingInfo,
    ZeroDowntimeInfo,
    FeatureToggleInfo,
)

logger = get_logger(__name__)

_BASE = "https://api.github.com"


class GitHubConnector(BasePlatformConnector):

    def __init__(self, credentials: dict) -> None:
        super().__init__(credentials)
        self._token = credentials.get("token", "")
        self._headers = {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    async def health_check(self) -> bool:
        url = f"{_BASE}/user"
        self._log(f"GET {url}")
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(url, headers=self._headers)
                return r.status_code == 200
        except Exception as exc:
            logger.error("GitHub health_check failed: %s", exc)
            return False

    async def collect(self, repository: str) -> DeploymentPlatformData:
        pd = DeploymentPlatformData(platform_type="github", repository=repository)

        owner, repo = (repository.split("/") + [""])[:2]
        await self._collect_workflows(pd, owner, repo)
        await self._collect_packages(pd, owner, repo)
        await self._collect_branch_protection(pd, owner, repo)
        await self._collect_dependabot(pd, owner, repo)

        pd.api_call_log = self._api_call_log
        return pd

    async def _collect_workflows(self, pd: DeploymentPlatformData, owner: str, repo: str) -> None:
        url = f"{_BASE}/repos/{owner}/{repo}/actions/workflows"
        self._log(f"GET {url}")
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(url, headers=self._headers)
            if r.status_code != 200:
                return
            workflows = r.json().get("workflows", [])

        for wf in workflows:
            raw = await self._fetch_workflow_content(owner, repo, wf.get("path", ""))
            content_lower = raw.lower()

            info = DeploymentPipelineInfo(
                name=wf.get("name", ""),
                path=wf.get("path", ""),
                raw_content=raw,
                has_deployment_job=any(k in content_lower for k in ("deploy", "release", "publish")),
                has_rollback_step="rollback" in content_lower,
                has_approval_gate=any(k in content_lower for k in ("environment:", "approval", "wait")),
                uses_iac=any(k in content_lower for k in ("terraform", "pulumi", "bicep", "arm template", "cloudformation")),
            )

            # Detect zero-downtime strategies
            if "blue" in content_lower and "green" in content_lower:
                pd.zero_downtime.blue_green_detected = True
                pd.zero_downtime.strategy = "blue_green"
            elif "rolling" in content_lower:
                pd.zero_downtime.rolling_update_detected = True
                if not pd.zero_downtime.strategy:
                    pd.zero_downtime.strategy = "rolling"

            # Feature toggles
            if any(k in content_lower for k in ("feature_flag", "feature toggle", "launchdarkly", "unleash", "flagsmith")):
                pd.feature_toggles.feature_flags_detected = True
            if "env:" in content_lower or "environment variables" in content_lower:
                pd.feature_toggles.env_var_toggles = True

            # Secrets management
            if any(k in content_lower for k in ("azure/get-keyvault-secrets", "key_vault", "keyvault")):
                pd.secrets.tool_detected = "azure_key_vault"
                pd.secrets.secrets_externalized = True
            elif any(k in content_lower for k in ("hashicorp/vault", "vault secrets")):
                pd.secrets.tool_detected = "hashicorp_vault"
                pd.secrets.secrets_externalized = True
            if "${{ secrets." in raw:
                pd.secrets.env_config_encrypted = True

            # Same artifact check
            if "same" in content_lower or ("staging" in content_lower and "production" in content_lower):
                pd.same_artifact_across_envs = True

            # Decommissioning
            if any(k in content_lower for k in ("kubectl delete", "docker rm", "decommission", "retire")):
                pd.decommissioning.process_documented = True
                pd.decommissioning.covers_containers = "docker" in content_lower
                pd.decommissioning.covers_kubernetes = "kubectl" in content_lower

            pd.pipelines.append(info)

    async def _fetch_workflow_content(self, owner: str, repo: str, path: str) -> str:
        if not path:
            return ""
        url = f"https://raw.githubusercontent.com/{owner}/{repo}/HEAD/{path}"
        self._log(f"GET {url}")
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(url, headers=self._headers)
                return r.text if r.status_code == 200 else ""
        except Exception:
            return ""

    async def _collect_packages(self, pd: DeploymentPlatformData, owner: str, repo: str) -> None:
        url = f"{_BASE}/repos/{owner}/{repo}/packages?package_type=container"
        self._log(f"GET {url}")
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(url, headers=self._headers)
                if r.status_code != 200:
                    return
                for pkg in r.json():
                    pd.artifacts.append(ArtifactInventoryInfo(
                        name=pkg.get("name", ""),
                        artifact_type="container_image",
                        tag=str(pkg.get("version", {}).get("name", "")),
                        source_verified=True,
                    ))
        except Exception as exc:
            logger.warning("_collect_packages failed: %s", exc)

    async def _collect_branch_protection(self, pd: DeploymentPlatformData, owner: str, repo: str) -> None:
        url = f"{_BASE}/repos/{owner}/{repo}/branches/main/protection"
        self._log(f"GET {url}")
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(url, headers=self._headers)
                if r.status_code == 200:
                    pd.raw_metadata["branch_protection"] = r.json()
        except Exception as exc:
            logger.warning("_collect_branch_protection failed: %s", exc)

    async def _collect_dependabot(self, pd: DeploymentPlatformData, owner: str, repo: str) -> None:
        url = f"{_BASE}/repos/{owner}/{repo}/vulnerability-alerts"
        self._log(f"GET {url}")
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(url, headers=self._headers)
                if r.status_code == 204:
                    pd.dependencies.vulnerabilities_tracked = True
                    pd.dependencies.tracking_tool_detected = "dependabot"
        except Exception as exc:
            logger.warning("_collect_dependabot failed: %s", exc)
