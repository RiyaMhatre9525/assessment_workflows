import httpx
import base64
from core.logger import get_logger
from workflows.deployment_domain.connectors.base import (
    BasePlatformConnector,
    DeploymentPlatformData,
    DeploymentPipelineInfo,
    ArtifactInventoryInfo,
    SecretsManagementInfo,
    DecommissioningInfo,
    ZeroDowntimeInfo,
    FeatureToggleInfo,
)

logger = get_logger(__name__)


class AzureDevOpsConnector(BasePlatformConnector):

    def __init__(self, credentials: dict) -> None:
        super().__init__(credentials)
        self._token = credentials.get("token", "")
        self._org = credentials.get("organization", "")
        encoded = base64.b64encode(f":{self._token}".encode()).decode()
        self._headers = {
            "Authorization": f"Basic {encoded}",
            "Content-Type": "application/json",
        }

    @property
    def _base(self) -> str:
        return f"https://dev.azure.com/{self._org}"

    async def health_check(self) -> bool:
        url = f"{self._base}/_apis/projects?api-version=7.1"
        self._log(f"GET {url}")
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(url, headers=self._headers)
                return r.status_code == 200
        except Exception as exc:
            logger.error("Azure DevOps health_check failed: %s", exc)
            return False

    async def collect(self, repository: str) -> DeploymentPlatformData:
        pd = DeploymentPlatformData(platform_type="azure_devops", repository=repository)

        # repository format: "project/repo"
        parts = repository.split("/")
        project = parts[0] if parts else ""

        await self._collect_release_pipelines(pd, project)
        await self._collect_artifacts(pd, project)

        pd.api_call_log = self._api_call_log
        return pd

    async def _collect_release_pipelines(self, pd: DeploymentPlatformData, project: str) -> None:
        url = f"{self._base}/{project}/_apis/release/definitions?api-version=7.1"
        self._log(f"GET {url}")
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.get(url, headers=self._headers)
                if r.status_code != 200:
                    return
                definitions = r.json().get("value", [])

            for defn in definitions:
                await self._enrich_pipeline(pd, project, defn)
        except Exception as exc:
            logger.warning("_collect_release_pipelines failed: %s", exc)

    async def _enrich_pipeline(self, pd: DeploymentPlatformData, project: str, defn: dict) -> None:
        defn_id = defn.get("id")
        url = f"{self._base}/{project}/_apis/release/definitions/{defn_id}?api-version=7.1"
        self._log(f"GET {url}")
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(url, headers=self._headers)
            if r.status_code != 200:
                return
            detail = r.json()

        raw = str(detail)
        raw_lower = raw.lower()

        info = DeploymentPipelineInfo(
            name=defn.get("name", ""),
            path=f"release/{defn_id}",
            raw_content=raw,
            has_deployment_job=True,
            has_rollback_step="rollback" in raw_lower,
            has_approval_gate=bool(detail.get("environments", [{}])[0].get("preDeployApprovals")),
            uses_iac=any(k in raw_lower for k in ("terraform", "bicep", "arm template", "pulumi")),
        )

        if "blue" in raw_lower and "green" in raw_lower:
            pd.zero_downtime.blue_green_detected = True
            pd.zero_downtime.strategy = "blue_green"
        elif "rolling" in raw_lower:
            pd.zero_downtime.rolling_update_detected = True
            if not pd.zero_downtime.strategy:
                pd.zero_downtime.strategy = "rolling"

        if "keyvault" in raw_lower or "key vault" in raw_lower:
            pd.secrets.tool_detected = "azure_key_vault"
            pd.secrets.secrets_externalized = True
            pd.secrets.env_config_encrypted = True

        if any(k in raw_lower for k in ("feature flag", "launchdarkly", "unleash")):
            pd.feature_toggles.feature_flags_detected = True

        if "kubectl delete" in raw_lower or "az aks" in raw_lower:
            pd.decommissioning.process_documented = True
            pd.decommissioning.covers_kubernetes = True

        pd.pipelines.append(info)

    async def _collect_artifacts(self, pd: DeploymentPlatformData, project: str) -> None:
        url = f"{self._base}/{project}/_apis/packaging/feeds?api-version=7.1"
        self._log(f"GET {url}")
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(url, headers=self._headers)
                if r.status_code != 200:
                    return
                for feed in r.json().get("value", []):
                    pd.artifacts.append(ArtifactInventoryInfo(
                        name=feed.get("name", ""),
                        artifact_type="package",
                        source_verified=True,
                        whitelist_approved=True,
                    ))
        except Exception as exc:
            logger.warning("_collect_artifacts failed: %s", exc)
