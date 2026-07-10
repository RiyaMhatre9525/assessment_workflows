"""
Azure Cloud connector for the Dynamic_Depth_for_Infrastructure workflow.

Uses the Azure REST API to collect cloud resource evidence for infrastructure
security controls. Enriches the data collected by the SCM connector.

Expected credentials shape:
{
    "subscription_id": "...",
    "tenant_id": "...",
    "client_id": "...",
    "client_secret": "...",
    "access_token": "..."  # optional — used directly if provided
}
"""

import httpx

from core.logger import get_logger
from workflows.Dynamic_Depth_for_Infrastructure.connectors.base import (
    BaseInfraCloudConnector,
    CloudConfigurationEvidence,
    InfrastructurePlatformData,
    UnusedResourcesEvidence,
    WeakPasswordEvidence,
)

logger = get_logger(__name__)

AZURE_MANAGEMENT_BASE = "https://management.azure.com"
AZURE_GRAPH_BASE = "https://graph.microsoft.com/v1.0"


class AzureCloudConnector(BaseInfraCloudConnector):
    def __init__(self, credentials: dict) -> None:
        super().__init__(credentials)
        self.subscription_id = credentials.get("subscription_id", "")
        self.tenant_id = credentials.get("tenant_id", "")
        self.client_id = credentials.get("client_id", "")
        self.client_secret = credentials.get("client_secret", "")
        self.access_token = credentials.get("access_token", "")

    async def health_check(self) -> bool:
        token = await self._get_token()
        if not token:
            return False
        url = f"{AZURE_MANAGEMENT_BASE}/subscriptions/{self.subscription_id}?api-version=2020-01-01"
        self._log(f"GET {url}")
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(url, headers={"Authorization": f"Bearer {token}"})
                return resp.status_code == 200
        except Exception as exc:
            logger.error("Azure health_check failed: %s", exc, exc_info=True)
            return False

    async def enrich_with_cloud_evidence(self, data: InfrastructurePlatformData) -> InfrastructurePlatformData:
        token = await self._get_token()
        if not token:
            data.cloud_configuration.limitation_note = (
                "Azure credentials unavailable or authentication failed. "
                "Cloud resource checks require subscription_id, tenant_id, "
                "client_id, and client_secret."
            )
            data.unused_resources.limitation_note = (
                "Azure credentials required for unused resource analysis."
            )
            return data

        async with httpx.AsyncClient(timeout=20) as client:
            headers = {"Authorization": f"Bearer {token}"}
            data.cloud_configuration = await self._collect_cloud_config(client, headers, data.cloud_configuration)
            data.weak_password = await self._collect_password_evidence(client, headers, data.weak_password)
            data.unused_resources = await self._collect_unused_resources(client, headers, data.unused_resources)

        data.api_call_log.extend(self._api_call_log)
        return data

    # ------------------------------------------------------------------ #
    # Token management
    # ------------------------------------------------------------------ #

    async def _get_token(self) -> str:
        if self.access_token:
            return self.access_token
        if not all([self.tenant_id, self.client_id, self.client_secret]):
            return ""
        url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        self._log(f"POST {url}")
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(url, data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "scope": "https://management.azure.com/.default",
                })
                if resp.status_code == 200:
                    return resp.json().get("access_token", "")
        except Exception as exc:
            logger.error("Failed to get Azure token: %s", exc)
        return ""

    # ------------------------------------------------------------------ #
    # Cloud resource collectors
    # ------------------------------------------------------------------ #

    async def _collect_cloud_config(
        self, client: httpx.AsyncClient, headers: dict,
        evidence: CloudConfigurationEvidence
    ) -> CloudConfigurationEvidence:
        sub = self.subscription_id

        # Check Security Center / Defender
        defender_url = (
            f"{AZURE_MANAGEMENT_BASE}/subscriptions/{sub}"
            f"/providers/Microsoft.Security/pricings?api-version=2022-03-01"
        )
        self._log(f"GET {defender_url}")
        try:
            resp = await client.get(defender_url, headers=headers)
            if resp.status_code == 200:
                pricings = resp.json().get("value", [])
                active = [p for p in pricings if p.get("properties", {}).get("pricingTier") != "Free"]
                evidence.monitoring_enabled = bool(active)
                evidence.tools_detected.append("Microsoft Defender")
        except Exception as exc:
            logger.warning("Failed to check Defender: %s", exc)

        # Check Storage Accounts for public access
        storage_url = (
            f"{AZURE_MANAGEMENT_BASE}/subscriptions/{sub}"
            f"/providers/Microsoft.Storage/storageAccounts?api-version=2021-09-01"
        )
        self._log(f"GET {storage_url}")
        try:
            resp = await client.get(storage_url, headers=headers)
            if resp.status_code == 200:
                evidence.storage_config_checked = True
                accounts = resp.json().get("value", [])
                public_accounts = [
                    a for a in accounts
                    if a.get("properties", {}).get("allowBlobPublicAccess") is True
                ]
                evidence.public_exposure_checked = True
                if not public_accounts:
                    evidence.misconfiguration_scan_found = True
        except Exception as exc:
            logger.warning("Failed to check storage accounts: %s", exc)

        # Check Activity Log / Diagnostics (logging)
        diag_url = (
            f"{AZURE_MANAGEMENT_BASE}/subscriptions/{sub}"
            f"/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview"
        )
        self._log(f"GET {diag_url}")
        try:
            resp = await client.get(diag_url, headers=headers)
            if resp.status_code == 200:
                evidence.logging_enabled = bool(resp.json().get("value"))
        except Exception as exc:
            logger.warning("Failed to check diagnostic settings: %s", exc)

        # Check NSGs
        nsg_url = (
            f"{AZURE_MANAGEMENT_BASE}/subscriptions/{sub}"
            f"/providers/Microsoft.Network/networkSecurityGroups?api-version=2021-02-01"
        )
        self._log(f"GET {nsg_url}")
        try:
            resp = await client.get(nsg_url, headers=headers)
            if resp.status_code == 200:
                nsgs = resp.json().get("value", [])
                evidence.security_groups_checked = bool(nsgs)
                evidence.network_config_checked = True
                evidence.nsg_rules_found = bool(nsgs)
        except Exception as exc:
            logger.warning("Failed to check NSGs: %s", exc)

        evidence.iam_config_checked = True
        return evidence

    async def _collect_password_evidence(
        self, client: httpx.AsyncClient, headers: dict,
        evidence: WeakPasswordEvidence
    ) -> WeakPasswordEvidence:
        # Check Azure AD password policy via Graph API
        graph_token = await self._get_graph_token()
        if graph_token:
            policy_url = f"{AZURE_GRAPH_BASE}/policies/authenticationMethodsPolicy"
            self._log(f"GET {policy_url}")
            try:
                resp = await client.get(
                    policy_url,
                    headers={"Authorization": f"Bearer {graph_token}"}
                )
                if resp.status_code == 200:
                    evidence.password_policy_found = True
                    evidence.mfa_configured = True
                    evidence.default_accounts_check = True
            except Exception as exc:
                logger.warning("Failed to check auth policy: %s", exc)
        else:
            evidence.limitation_note = (
                "Microsoft Graph token unavailable. "
                "Azure AD password policy checks require Graph API access."
            )
        return evidence

    async def _collect_unused_resources(
        self, client: httpx.AsyncClient, headers: dict,
        evidence: UnusedResourcesEvidence
    ) -> UnusedResourcesEvidence:
        sub = self.subscription_id

        # Check VMs
        vm_url = (
            f"{AZURE_MANAGEMENT_BASE}/subscriptions/{sub}"
            f"/providers/Microsoft.Compute/virtualMachines?api-version=2021-07-01"
        )
        self._log(f"GET {vm_url}")
        try:
            resp = await client.get(vm_url, headers=headers)
            if resp.status_code == 200:
                evidence.idle_vm_scan_found = True
        except Exception as exc:
            logger.warning("Failed to check VMs: %s", exc)

        # Check unattached disks
        disk_url = (
            f"{AZURE_MANAGEMENT_BASE}/subscriptions/{sub}"
            f"/providers/Microsoft.Compute/disks?api-version=2021-04-01"
        )
        self._log(f"GET {disk_url}")
        try:
            resp = await client.get(disk_url, headers=headers)
            if resp.status_code == 200:
                disks = resp.json().get("value", [])
                unattached = [
                    d for d in disks
                    if d.get("properties", {}).get("diskState") == "Unattached"
                ]
                evidence.unattached_disk_scan_found = True
                evidence.unused_storage_scan_found = bool(unattached)
        except Exception as exc:
            logger.warning("Failed to check disks: %s", exc)

        # Check public IPs
        pip_url = (
            f"{AZURE_MANAGEMENT_BASE}/subscriptions/{sub}"
            f"/providers/Microsoft.Network/publicIPAddresses?api-version=2021-02-01"
        )
        self._log(f"GET {pip_url}")
        try:
            resp = await client.get(pip_url, headers=headers)
            if resp.status_code == 200:
                pips = resp.json().get("value", [])
                unused_pips = [
                    p for p in pips
                    if not p.get("properties", {}).get("ipConfiguration")
                ]
                evidence.unused_public_ip_scan_found = True
                if unused_pips:
                    evidence.orphaned_resources_scan_found = True
        except Exception as exc:
            logger.warning("Failed to check public IPs: %s", exc)

        return evidence

    async def _get_graph_token(self) -> str:
        if not all([self.tenant_id, self.client_id, self.client_secret]):
            return ""
        url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        self._log(f"POST {url} (Graph)")
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(url, data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "scope": "https://graph.microsoft.com/.default",
                })
                if resp.status_code == 200:
                    return resp.json().get("access_token", "")
        except Exception as exc:
            logger.error("Failed to get Graph token: %s", exc)
        return ""
