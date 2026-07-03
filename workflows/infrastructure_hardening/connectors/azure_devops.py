"""
workflows/infrastructure_hardening/connectors/azure_devops.py

Azure DevOps VCS connector. Collects VCS-observable evidence relevant to
Level 1-3 access-control and RBAC criteria:
  - Branch policy configurations (proxy for RBAC / required reviewers)
  - Administrators group size (proxy for admin count <=5 criterion)
"""

from __future__ import annotations

import httpx

from core.logger import get_logger
from workflows.infrastructure_hardening.connectors.base import (
    BaseVCSConnector,
    PlatformData,
)

logger = get_logger(__name__)

ADO_API_VERSION = "7.1"


class AzureDevOpsConnector(BaseVCSConnector):

    def _base_url(self) -> str:
        org = self.credentials.get("organization", "")
        return f"https://dev.azure.com/{org}"

    async def health_check(self) -> bool:
        token = self.credentials.get("token", "")
        url = f"{self._base_url()}/_apis/projects?api-version={ADO_API_VERSION}"
        self._log(f"GET {url}")
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(url, auth=("", token))
                return resp.status_code == 200
        except Exception as exc:
            logger.error("Azure DevOps health_check failed: %s", exc, exc_info=True)
            return False

    async def collect(self, repository: str, platform_data: PlatformData) -> PlatformData:
        token = self.credentials.get("token", "")
        project = self.credentials.get("project", repository)

        async with httpx.AsyncClient(timeout=20.0) as client:
            # --- Branch policy configurations (RBAC signal) ---
            policies_url = (
                f"{self._base_url()}/{project}/_apis/policy/configurations"
                f"?api-version={ADO_API_VERSION}"
            )
            self._log(f"GET {policies_url}")
            policies: list = []
            try:
                resp = await client.get(policies_url, auth=("", token))
                if resp.status_code == 200:
                    policies = resp.json().get("value", [])
                else:
                    logger.warning("Azure DevOps policy fetch returned %s", resp.status_code)
            except Exception as exc:
                logger.error("Azure DevOps policy fetch failed: %s", exc, exc_info=True)

            platform_data.access_control.rbac_enabled = len(policies) > 0

            # --- Administrators group size (proxy for admin count) ---
            groups_url = f"{self._base_url()}/_apis/graph/groups?api-version={ADO_API_VERSION}"
            self._log(f"GET {groups_url}")
            groups: list = []
            try:
                resp = await client.get(groups_url, auth=("", token))
                if resp.status_code == 200:
                    groups = resp.json().get("value", [])
                else:
                    logger.warning("Azure DevOps groups fetch returned %s", resp.status_code)
            except Exception as exc:
                logger.error("Azure DevOps groups fetch failed: %s", exc, exc_info=True)

            admin_groups = [g for g in groups if "Administrators" in g.get("displayName", "")]
            platform_data.access_control.admin_count = len(admin_groups)

            platform_data.raw_metadata["ado_policies"] = policies
            platform_data.raw_metadata["ado_admin_groups"] = admin_groups

        platform_data.vcs_type = "azure_devops"
        platform_data.repository = repository
        platform_data.api_call_log.extend(self._api_call_log)
        return platform_data
