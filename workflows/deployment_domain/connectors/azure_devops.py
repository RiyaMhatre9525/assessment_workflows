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

    async def collect(self, repository: str, branch: str = "main") -> DeploymentPlatformData:
        pd = DeploymentPlatformData(platform_type="azure_devops", repository=repository)

        # repository format: "project/repo"
        parts = repository.split("/")
        project = parts[0] if parts else ""
        repo_name = parts[1] if len(parts) > 1 else ""

        await self._collect_build_pipelines(pd, project, repo_name, branch)
        await self._collect_release_pipelines(pd, project, branch)
        await self._collect_artifacts(pd, project)
        await self._collect_branch_policies(pd, project, repo_name, branch)

        pd.api_call_log = self._api_call_log
        return pd

    async def _collect_build_pipelines(self, pd: DeploymentPlatformData, project: str, repo_name: str, branch: str) -> None:
        # Fetch YAML build pipelines filtered to the target branch
        url = f"{self._base}/{project}/_apis/pipelines?api-version=7.1"
        self._log(f"GET {url}")
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.get(url, headers=self._headers)
                if r.status_code != 200:
                    return
                pipelines = r.json().get("value", [])

            for pl in pipelines:
                await self._enrich_build_pipeline(pd, project, pl, branch)
        except Exception as exc:
            logger.warning("_collect_build_pipelines failed: %s", exc)

    async def _enrich_build_pipeline(self, pd: DeploymentPlatformData, project: str, pl: dict, branch: str) -> None:
        pl_id = pl.get("id")

        # Fetch the actual pipeline definition to get YAML content
        url = f"{self._base}/{project}/_apis/pipelines/{pl_id}?api-version=7.1"
        self._log(f"GET {url}")
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(url, headers=self._headers)
            if r.status_code != 200:
                return
            detail = r.json()

        # Fetch the YAML file content via the repository path in the definition
        yaml_path = detail.get("configuration", {}).get("path", "")
        repo_id = detail.get("configuration", {}).get("repository", {}).get("id", "")
        yaml_content = ""
        if yaml_path and repo_id:
            yaml_url = f"{self._base}/{project}/_apis/git/repositories/{repo_id}/items?path={yaml_path}&versionDescriptor.version={branch}&versionDescriptor.versionType=branch&api-version=7.1"
            self._log(f"GET {yaml_url}")
            async with httpx.AsyncClient(timeout=10) as client:
                yr = await client.get(yaml_url, headers=self._headers)
                if yr.status_code == 200:
                    yaml_content = yr.text

        raw = yaml_content or str(detail)
        raw_lower = raw.lower()

        # Only skip if runs exist but none match the branch
        runs_url = f"{self._base}/{project}/_apis/pipelines/{pl_id}/runs?api-version=7.1&$top=5"
        self._log(f"GET {runs_url}")
        async with httpx.AsyncClient(timeout=10) as client:
            rr = await client.get(runs_url, headers=self._headers)
            runs = rr.json().get("value", []) if rr.status_code == 200 else []

        branch_runs = [
            run for run in runs
            if run.get("resources", {}).get("repositories", {}).get("self", {}).get("refName", "") in
            (f"refs/heads/{branch}", branch)
        ]
        if runs and not branch_runs:
            return

        info = DeploymentPipelineInfo(
            name=pl.get("name", ""),
            path=f"build/{pl_id}",
            raw_content=raw,
            has_deployment_job=any(k in raw_lower for k in ("deploy", "release", "publish")),
            has_rollback_step="rollback" in raw_lower,
            has_approval_gate=any(k in raw_lower for k in ("environment:", "approval", "wait")),
            uses_iac=any(k in raw_lower for k in ("terraform", "bicep", "arm template", "pulumi")),
        )
        self._apply_signals(pd, raw, raw_lower)
        pd.pipelines.append(info)

    async def _collect_release_pipelines(self, pd: DeploymentPlatformData, project: str, branch: str) -> None:
        url = f"{self._base}/{project}/_apis/release/definitions?api-version=7.1"
        self._log(f"GET {url}")
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.get(url, headers=self._headers)
                if r.status_code != 200:
                    return
                definitions = r.json().get("value", [])

            for defn in definitions:
                await self._enrich_release_pipeline(pd, project, defn, branch)
        except Exception as exc:
            logger.warning("_collect_release_pipelines failed: %s", exc)

    async def _enrich_release_pipeline(self, pd: DeploymentPlatformData, project: str, defn: dict, branch: str) -> None:
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

        # NEW
        artifacts = detail.get("artifacts", [])
        branch_matched = any(
            a.get("definitionReference", {}).get("branch", {}).get("name", "") in (branch, f"refs/heads/{branch}")
            for a in artifacts
        )
        # Only skip if branch info is explicitly set AND doesn't match — empty branch field means no filter
        has_branch_set = any(
            a.get("definitionReference", {}).get("branch", {}).get("name", "")
            for a in artifacts
        )
        if has_branch_set and not branch_matched:
            return

        info = DeploymentPipelineInfo(
            name=defn.get("name", ""),
            path=f"release/{defn_id}",
            raw_content=raw,
            has_deployment_job=True,
            has_rollback_step="rollback" in raw_lower,
            has_approval_gate=bool(detail.get("environments", [{}])[0].get("preDeployApprovals")),
            uses_iac=any(k in raw_lower for k in ("terraform", "bicep", "arm template", "pulumi")),
        )
        self._apply_signals(pd, raw, raw_lower)
        pd.pipelines.append(info)

    def _apply_signals(self, pd: DeploymentPlatformData, raw: str, raw_lower: str) -> None:
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

        if any(k in raw_lower for k in ("staging", "production", "prod")):
            pd.same_artifact_across_envs = True

        if "kubectl delete" in raw_lower or "az aks" in raw_lower:
            pd.decommissioning.process_documented = True
            pd.decommissioning.covers_kubernetes = True

    async def _collect_branch_policies(self, pd: DeploymentPlatformData, project: str, repo_name: str, branch: str) -> None:
        # Fetch branch policies scoped to the target branch
        url = f"{self._base}/{project}/_apis/policy/configurations?api-version=7.1"
        self._log(f"GET {url}")
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(url, headers=self._headers)
                if r.status_code != 200:
                    return
                policies = r.json().get("value", [])

            branch_policies = [
                p for p in policies
                if p.get("settings", {}).get("scope", [{}])[0].get("refName", "") in
                   (f"refs/heads/{branch}", branch)
            ]
            pd.raw_metadata["branch_policies"] = branch_policies
        except Exception as exc:
            logger.warning("_collect_branch_policies failed: %s", exc)

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