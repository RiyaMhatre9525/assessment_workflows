"""
Azure cloud connector for the Static_Depth_for_Infrastructure workflow.

This connector is central to this workflow (unlike the application-focused
workflows, where cloud evidence was only supplementary) because several
criteria are fundamentally about deployed infrastructure, not source code:
  - Test Cluster Deployment Resources  -> AKS cluster presence/config
  - Test Cloud Configuration           -> Defender for Cloud / Azure Policy
  - Test Virtualized Environments      -> VM/Defender for Servers plan
  - Test for Malware                   -> Defender for Containers/Storage
  - SCA / Known Vulnerabilities        -> Defender vulnerability assessment
                                           plans on registries/VMs
"""

from __future__ import annotations

import httpx

from core.logger import get_logger
from workflows.Static_Depth_for_Infrastructure.connectors.base import (
    BaseCloudConnector,
    CloudInfrastructureEvidence,
)

logger = get_logger(__name__)

TOKEN_URL_TEMPLATE = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
ARM_BASE = "https://management.azure.com"
ARM_API_VERSION = "2021-04-01"
SECURITY_API_VERSION = "2022-03-01"

# Defender for Cloud plan name -> criteria it provides supporting evidence for.
DEFENDER_PLAN_SIGNALS: dict[str, list[str]] = {
    "Containers": ["Test for Malware", "Test Infrastructure Components for Known Vulnerabilities", "Software Composition Analysis (SCA)"],
    "ContainerRegistry": ["Software Composition Analysis (SCA)", "Test Infrastructure Components for Known Vulnerabilities"],
    "VirtualMachines": ["Test Virtualized Environments", "Test Infrastructure Components for Known Vulnerabilities"],
    "CloudPosture": ["Test Cloud Configuration"],
    "Arm": ["Test Cloud Configuration"],
    "StorageAccounts": ["Test for Malware"],
}

RESOURCE_TYPE_SIGNALS: dict[str, str] = {
    "Microsoft.ContainerService/managedClusters": "Test Cluster Deployment Resources",
    "Microsoft.ContainerRegistry/registries": "Test for New Image Version",
}


class AzureCloudConnector(BaseCloudConnector):
    """
    Expected credentials:
        {
            "tenant_id": "...",
            "client_id": "...",
            "client_secret": "...",
            "subscription_id": "..."
        }
    """

    def __init__(self, credentials: dict) -> None:
        super().__init__(credentials)
        self.tenant_id = credentials.get("tenant_id", "")
        self.client_id = credentials.get("client_id", "")
        self.client_secret = credentials.get("client_secret", "")
        self.subscription_id = credentials.get("subscription_id", "")
        self._access_token: str | None = None

    async def _get_token(self, client: httpx.AsyncClient) -> str | None:
        if self._access_token:
            return self._access_token

        url = TOKEN_URL_TEMPLATE.format(tenant_id=self.tenant_id)
        self._log(f"POST {url}")
        try:
            response = await client.post(
                url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "scope": "https://management.azure.com/.default",
                },
            )
            response.raise_for_status()
            self._access_token = response.json().get("access_token")
            return self._access_token
        except Exception as exc:
            logger.error("Azure token acquisition failed: %s", exc)
            return None

    async def health_check(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                token = await self._get_token(client)
                return token is not None
        except Exception as exc:
            logger.error("Azure cloud health_check failed: %s", exc)
            return False

    async def collect(self, scope: str) -> CloudInfrastructureEvidence:
        subscription_id = scope or self.subscription_id
        signals: dict[str, list[str]] = {}
        enabled_plans: list[str] = []
        resource_summary: dict[str, int] = {}

        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                token = await self._get_token(client)
                if not token:
                    raise RuntimeError("Unable to acquire Azure access token")

                headers = {"Authorization": f"Bearer {token}"}

                # --- Defender for Cloud plans ---
                pricing_url = (
                    f"{ARM_BASE}/subscriptions/{subscription_id}/providers/Microsoft.Security/pricings"
                    f"?api-version={SECURITY_API_VERSION}"
                )
                self._log(f"GET {pricing_url}")
                pricing_resp = await client.get(pricing_url, headers=headers)
                pricing_resp.raise_for_status()
                for plan in pricing_resp.json().get("value", []):
                    name = plan.get("name", "")
                    tier = plan.get("properties", {}).get("pricingTier", "")
                    if tier and tier.lower() == "standard":
                        enabled_plans.append(name)
                        for criterion in DEFENDER_PLAN_SIGNALS.get(name, []):
                            signals.setdefault(criterion, [])
                            signals[criterion].append(f"Defender for Cloud plan '{name}' is Standard tier")

                # --- Deployed resources (AKS, ACR presence) ---
                resources_url = (
                    f"{ARM_BASE}/subscriptions/{subscription_id}/resources"
                    f"?api-version={ARM_API_VERSION}"
                )
                self._log(f"GET {resources_url}")
                resources_resp = await client.get(resources_url, headers=headers)
                resources_resp.raise_for_status()
                resources = resources_resp.json().get("value", [])

                detected_types = [r.get("type", "") for r in resources]
                for resource_type, criterion in RESOURCE_TYPE_SIGNALS.items():
                    count = detected_types.count(resource_type)
                    if count > 0:
                        resource_summary[resource_type] = count
                        signals.setdefault(criterion, [])
                        signals[criterion].append(f"{count} resource(s) of type {resource_type} found")
        except Exception as exc:
            logger.error("Azure cloud collection failed: %s", exc, exc_info=True)

        return CloudInfrastructureEvidence(
            platform_type="azure",
            scope=subscription_id,
            detected_signals=signals,
            raw_metadata={"defender_plans_enabled": enabled_plans, "resource_summary": resource_summary},
            api_call_log=self._api_call_log,
        )
