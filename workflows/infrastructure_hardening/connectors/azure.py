"""
workflows/infrastructure_hardening/connectors/azure.py

Azure cloud connector. Collects cloud-infrastructure evidence via the
Azure Resource Manager (ARM) API relevant to Level 1-5 criteria:
encryption at rest, network isolation/egress filtering, WAF posture,
automated backups, resource limits, and Infrastructure-as-Code provenance.
"""

from __future__ import annotations

import httpx

from core.logger import get_logger
from workflows.infrastructure_hardening.connectors.base import (
    BaseCloudConnector,
    PlatformData,
)

logger = get_logger(__name__)

ARM_BASE = "https://management.azure.com"
ARM_API_VERSION = "2023-09-01"


class AzureCloudConnector(BaseCloudConnector):

    async def health_check(self) -> bool:
        token = self.credentials.get("access_token", "")
        subscription_id = self.credentials.get("subscription_id", "")
        url = f"{ARM_BASE}/subscriptions/{subscription_id}?api-version=2022-12-01"
        self._log(f"GET {url}")
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(url, headers={"Authorization": f"Bearer {token}"})
                return resp.status_code == 200
        except Exception as exc:
            logger.error("Azure health_check failed: %s", exc, exc_info=True)
            return False

    async def collect(self, repository: str, platform_data: PlatformData) -> PlatformData:
        token = self.credentials.get("access_token", "")
        subscription_id = self.credentials.get("subscription_id", "")
        resource_group = self.credentials.get("resource_group", "")
        headers = {"Authorization": f"Bearer {token}"}

        async with httpx.AsyncClient(timeout=20.0) as client:
            # --- Virtual machines: resource limits, encryption, virtualization ---
            vms_url = (
                f"{ARM_BASE}/subscriptions/{subscription_id}/resourceGroups/"
                f"{resource_group}/providers/Microsoft.Compute/virtualMachines"
                f"?api-version={ARM_API_VERSION}"
            )
            self._log(f"GET {vms_url}")
            vms: list = []
            try:
                resp = await client.get(vms_url, headers=headers)
                if resp.status_code == 200:
                    vms = resp.json().get("value", [])
                else:
                    logger.warning("Azure VM fetch returned %s", resp.status_code)
            except Exception as exc:
                logger.error("Azure VM fetch failed: %s", exc, exc_info=True)

            disk_encrypted = any(
                vm.get("properties", {}).get("storageProfile", {})
                  .get("osDisk", {}).get("encryptionSettings", {}).get("enabled")
                for vm in vms
            )
            platform_data.encryption.encryption_at_rest_enabled = disk_encrypted
            platform_data.encryption.disk_encryption_type = (
                "Azure Disk Encryption" if disk_encrypted else ""
            )

            platform_data.infrastructure.resource_limits_enforced = bool(vms) and all(
                vm.get("properties", {}).get("hardwareProfile", {}).get("vmSize") for vm in vms
            )
            platform_data.infrastructure.virtualized_environments = len(vms) > 0

            # --- IaC provenance signal via resource tags ---
            iac_detected = any(
                any(kw in str(vm.get("tags", {})).lower() for kw in ("iac", "terraform", "bicep", "arm-template"))
                for vm in vms
            )
            platform_data.infrastructure.iac_managed = iac_detected
            if iac_detected:
                platform_data.infrastructure.iac_tool = "detected via resource tags"

            # --- Network Security Groups: isolation + egress filtering ---
            nsg_url = (
                f"{ARM_BASE}/subscriptions/{subscription_id}/resourceGroups/"
                f"{resource_group}/providers/Microsoft.Network/networkSecurityGroups"
                f"?api-version={ARM_API_VERSION}"
            )
            self._log(f"GET {nsg_url}")
            nsgs: list = []
            try:
                resp = await client.get(nsg_url, headers=headers)
                if resp.status_code == 200:
                    nsgs = resp.json().get("value", [])
                else:
                    logger.warning("Azure NSG fetch returned %s", resp.status_code)
            except Exception as exc:
                logger.error("Azure NSG fetch failed: %s", exc, exc_info=True)

            has_deny_egress_rule = False
            for nsg in nsgs:
                for rule in nsg.get("properties", {}).get("securityRules", []):
                    props = rule.get("properties", {})
                    if props.get("direction") == "Outbound" and props.get("access") == "Deny":
                        has_deny_egress_rule = True
            platform_data.network.egress_filtering_enabled = has_deny_egress_rule
            platform_data.network.network_isolation_enabled = len(nsgs) > 0

            # --- Application Gateway WAF policy ---
            waf_url = (
                f"{ARM_BASE}/subscriptions/{subscription_id}/resourceGroups/"
                f"{resource_group}/providers/Microsoft.Network/"
                f"applicationGatewayWebApplicationFirewallPolicies"
                f"?api-version={ARM_API_VERSION}"
            )
            self._log(f"GET {waf_url}")
            wafs: list = []
            try:
                resp = await client.get(waf_url, headers=headers)
                if resp.status_code == 200:
                    wafs = resp.json().get("value", [])
                else:
                    logger.warning("Azure WAF fetch returned %s", resp.status_code)
            except Exception as exc:
                logger.error("Azure WAF fetch failed: %s", exc, exc_info=True)

            if wafs:
                mode_raw = wafs[0].get("properties", {}).get("policySettings", {}).get("mode", "")
                if mode_raw == "Detection":
                    platform_data.network.waf_mode = "monitoring"
                elif mode_raw == "Prevention":
                    platform_data.network.waf_mode = "medium"
                custom_rules = wafs[0].get("properties", {}).get("customRules", [])
                platform_data.network.waf_custom_rule_count = len(custom_rules)
                platform_data.network.waf_ml_detection = any(
                    "anomaly" in str(rule).lower() or "ml" in str(rule).lower()
                    for rule in custom_rules
                )

            # --- Recovery Services vaults: automated backups ---
            backup_url = (
                f"{ARM_BASE}/subscriptions/{subscription_id}/resourceGroups/"
                f"{resource_group}/providers/Microsoft.RecoveryServices/vaults"
                f"?api-version=2023-04-01"
            )
            self._log(f"GET {backup_url}")
            vaults: list = []
            try:
                resp = await client.get(backup_url, headers=headers)
                if resp.status_code == 200:
                    vaults = resp.json().get("value", [])
                else:
                    logger.warning("Azure backup vault fetch returned %s", resp.status_code)
            except Exception as exc:
                logger.error("Azure backup vault fetch failed: %s", exc, exc_info=True)

            platform_data.backup.automated_backups_enabled = len(vaults) > 0

            platform_data.raw_metadata["vm_count"] = len(vms)
            platform_data.raw_metadata["nsg_count"] = len(nsgs)
            platform_data.raw_metadata["waf_policy_count"] = len(wafs)
            platform_data.raw_metadata["backup_vault_count"] = len(vaults)

        platform_data.cloud_type = "azure"
        platform_data.api_call_log.extend(self._api_call_log)
        return platform_data
