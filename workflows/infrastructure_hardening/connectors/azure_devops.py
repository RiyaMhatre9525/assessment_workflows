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
ADO_GRAPH_API_VERSION = "7.1-preview"  # Graph endpoints require the -preview suffix


class AzureDevOpsConnector(BaseVCSConnector):

    def _base_url(self) -> str:
        org = self.credentials.get("organization", "")
        return f"https://dev.azure.com/{org}"

    def _vssps_url(self) -> str:
        """Azure DevOps Graph API lives on the VSSPS subdomain, not dev.azure.com."""
        org = self.credentials.get("organization", "")
        return f"https://vssps.dev.azure.com/{org}"

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

            # --- Administrators group analysis ---
            # NOTE: ADO returns one "Administrators" group PER project plus
            # org-level groups (Build Administrators, Release Administrators,
            # etc.). Counting ALL of them gives 50+ and is NOT the same as the
            # number of admin USERS required by the "admin count ≤ 5" criterion.
            #
            # We do NOT set access_control.admin_count here — that field is
            # owned by the Azure RBAC check in the cloud connector, which counts
            # actual privileged-role principals at the subscription level.
            # Instead we record the org-level collection admin group names in
            # raw_metadata so the LLM can see that context.
            groups_url = f"{self._vssps_url()}/_apis/graph/groups?api-version={ADO_GRAPH_API_VERSION}"
            self._log(f"GET {groups_url}")
            groups: list = []
            try:
                resp = await client.get(groups_url, auth=("", token))
                if resp.status_code == 200:
                    groups = resp.json().get("value", [])
                else:
                    logger.warning(
                        "Azure DevOps groups fetch returned %s — body: %s",
                        resp.status_code,
                        resp.text[:300],
                    )
            except Exception as exc:
                logger.error("Azure DevOps groups fetch failed: %s", exc, exc_info=True)

            all_admin_groups = [
                g.get("displayName", "") for g in groups
                if "Administrators" in g.get("displayName", "")
            ]
            collection_admin_groups = [
                name for name in all_admin_groups
                if "Project Collection" in name or "Organization" in name
            ]
            logger.info(
                "Azure DevOps: %d total groups, %d Administrators-named groups, "
                "%d collection-level admin group(s)",
                len(groups),
                len(all_admin_groups),
                len(collection_admin_groups),
            )

            platform_data.raw_metadata["ado_total_groups"] = len(groups)
            platform_data.raw_metadata["ado_admin_group_count"] = len(all_admin_groups)
            platform_data.raw_metadata["ado_collection_admin_groups"] = collection_admin_groups
            platform_data.raw_metadata["ado_policies"] = policies

        platform_data.vcs_type = "azure_devops"
        platform_data.repository = repository

        # MFA status is not queryable via Azure DevOps PAT tokens —
        # PAT tokens are scoped to ADO only and cannot reach Azure AD /
        # Entra ID. MFA policy is managed at the AAD tenant level.
        # The LLM should rely on the Azure Cloud connector's
        # graph_mfa_policy_state in raw_metadata for MFA determination.
        platform_data.raw_metadata["mfa_data_source"] = (
            "not_available_via_ado_pat — MFA is an Azure AD tenant policy; "
            "check graph_mfa_policy_state from the Azure cloud connector."
        )

        platform_data.api_call_log.extend(self._api_call_log)
        return platform_data
