"""
workflows/infrastructure_hardening/connectors/azure.py

Azure cloud connector. Collects cloud-infrastructure evidence via the
Azure Resource Manager (ARM) API and optionally Microsoft Graph, relevant
to Level 1-5 criteria.

API calls made per collect():
  ARM:
    - /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines
    - /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/networkSecurityGroups
    - /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/applicationGatewayWebApplicationFirewallPolicies
    - /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.RecoveryServices/vaults
    - /subscriptions/{sub}/providers/Microsoft.Authorization/roleAssignments   (admin count)
    - /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Web/sites   (HTTPS enforcement)
    - /subscriptions/{sub}/resourceGroups                                       (test/prod env detection)
    - /subscriptions/{sub}/providers/Microsoft.OperationsManagement/solutions  (Sentinel / security account)
  Graph (optional — graceful skip if ARM token lacks Graph.Policy scope):
    - /v1.0/policies/authenticationMethodsPolicy                               (MFA enforcement state)
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
GRAPH_BASE = "https://graph.microsoft.com"

# Privileged Azure built-in role definition IDs (last UUID segment)
_PRIVILEGED_ROLE_IDS = {
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",  # Owner
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",  # User Access Administrator
}


class AzureCloudConnector(BaseCloudConnector):

    async def health_check(self) -> bool:
        token = self.credentials.get("access_token", "")
        subscription_id = self.credentials.get("subscription_id", "")
        url = f"{ARM_BASE}/subscriptions/{subscription_id}?api-version=2022-12-01"
        self._log(f"GET {url}")
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(url, headers={"Authorization": f"Bearer {token}"})
                if resp.status_code == 200:
                    return True
                logger.error(
                    "Azure health_check failed. URL: %s, Status Code: %s, Response: %s",
                    url,
                    resp.status_code,
                    resp.text,
                )
                return False
        except Exception as exc:
            logger.error("Azure health_check failed with exception: %s", exc, exc_info=True)
            return False

    async def collect(self, repository: str, platform_data: PlatformData) -> PlatformData:  # noqa: PLR0912,PLR0915
        token = self.credentials.get("access_token", "")
        subscription_id = self.credentials.get("subscription_id", "")
        resource_group = self.credentials.get("resource_group", "")
        headers = {"Authorization": f"Bearer {token}"}

        async with httpx.AsyncClient(timeout=20.0) as client:

            # ----------------------------------------------------------------
            # Virtual machines: resource limits, encryption, virtualization,
            # IaC provenance signal via resource tags
            # ----------------------------------------------------------------
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

            iac_detected = any(
                any(kw in str(vm.get("tags", {})).lower()
                    for kw in ("iac", "terraform", "bicep", "arm-template"))
                for vm in vms
            )
            platform_data.infrastructure.iac_managed = iac_detected
            if iac_detected:
                platform_data.infrastructure.iac_tool = "detected via resource tags"

            # ----------------------------------------------------------------
            # Network Security Groups: isolation + egress filtering
            # ----------------------------------------------------------------
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

            # ----------------------------------------------------------------
            # Application Gateway WAF policy
            # ----------------------------------------------------------------
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

            # ----------------------------------------------------------------
            # Recovery Services vaults: automated backups
            # ----------------------------------------------------------------
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

            # ----------------------------------------------------------------
            # RBAC role assignments: admin count at subscription scope (Level 1)
            # Counts Owner + User Access Administrator assignments as "admin".
            # ----------------------------------------------------------------
            rbac_url = (
                f"{ARM_BASE}/subscriptions/{subscription_id}"
                f"/providers/Microsoft.Authorization/roleAssignments"
                f"?api-version=2022-04-01"
            )
            self._log(f"GET {rbac_url}")
            try:
                resp = await client.get(rbac_url, headers=headers)
                if resp.status_code == 200:
                    assignments = resp.json().get("value", [])
                    admin_count = sum(
                        1 for a in assignments
                        if a.get("properties", {})
                             .get("roleDefinitionId", "").split("/")[-1]
                        in _PRIVILEGED_ROLE_IDS
                    )
                    if admin_count > 0:
                        # Only override if VCS connector hasn't already set a more precise value
                        if platform_data.access_control.admin_count == 0:
                            platform_data.access_control.admin_count = admin_count
                    platform_data.raw_metadata["rbac_privileged_role_assignments"] = admin_count
                    logger.info("Azure RBAC: %d privileged role assignment(s) found", admin_count)
                else:
                    logger.warning("Azure RBAC fetch returned %s", resp.status_code)
            except Exception as exc:
                logger.error("Azure RBAC fetch failed: %s", exc, exc_info=True)

            # ----------------------------------------------------------------
            # App Services: edge HTTPS-only enforcement (Level 1)
            # Falls back to WAF presence as proxy if no App Services found.
            # ----------------------------------------------------------------
            app_url = (
                f"{ARM_BASE}/subscriptions/{subscription_id}/resourceGroups/"
                f"{resource_group}/providers/Microsoft.Web/sites"
                f"?api-version=2022-09-01"
            )
            self._log(f"GET {app_url}")
            try:
                resp = await client.get(app_url, headers=headers)
                if resp.status_code == 200:
                    sites = resp.json().get("value", [])
                    if sites:
                        https_enforced = all(
                            s.get("properties", {}).get("httpsOnly", False)
                            for s in sites
                        )
                        platform_data.encryption.edge_https_enforced = https_enforced
                        platform_data.raw_metadata["app_service_count"] = len(sites)
                        platform_data.raw_metadata["app_services_https_only"] = https_enforced
                    elif wafs:
                        # No App Services present but WAF (Application Gateway) found —
                        # Application Gateway enforces HTTPS at the edge.
                        platform_data.encryption.edge_https_enforced = True
                        platform_data.raw_metadata["edge_https_source"] = "application_gateway_waf"
                else:
                    logger.warning("Azure App Service fetch returned %s", resp.status_code)
            except Exception as exc:
                logger.error("Azure App Service fetch failed: %s", exc, exc_info=True)

            # ----------------------------------------------------------------
            # Resource groups: test/production environment separation (Level 2)
            # Detects naming patterns that indicate separate env lifecycle.
            # ----------------------------------------------------------------
            rg_list_url = (
                f"{ARM_BASE}/subscriptions/{subscription_id}/resourceGroups"
                f"?api-version=2022-09-01"
            )
            self._log(f"GET {rg_list_url}")
            try:
                resp = await client.get(rg_list_url, headers=headers)
                if resp.status_code == 200:
                    rg_names = [rg["name"].lower() for rg in resp.json().get("value", [])]
                    has_prod = any(
                        kw in n for n in rg_names
                        for kw in ("prod", "production", "prd", "live")
                    )
                    has_test = any(
                        kw in n for n in rg_names
                        for kw in ("test", "dev", "staging", "qa", "uat", "sandbox")
                    )
                    platform_data.environment.test_env_separate = has_prod and has_test
                    platform_data.raw_metadata["resource_group_count"] = len(rg_names)
                    platform_data.raw_metadata["has_prod_resource_group"] = has_prod
                    platform_data.raw_metadata["has_test_resource_group"] = has_test
                else:
                    logger.warning("Azure resource group list returned %s", resp.status_code)
            except Exception as exc:
                logger.error("Azure resource group list failed: %s", exc, exc_info=True)

            # ----------------------------------------------------------------
            # Microsoft Sentinel: dedicated security account proxy (Level 2)
            # Sentinel presence indicates a dedicated security operations tool/
            # account is configured for the subscription.
            # ----------------------------------------------------------------
            sentinel_url = (
                f"{ARM_BASE}/subscriptions/{subscription_id}"
                f"/providers/Microsoft.OperationsManagement/solutions"
                f"?api-version=2015-11-01-preview"
            )
            self._log(f"GET {sentinel_url}")
            try:
                resp = await client.get(sentinel_url, headers=headers)
                if resp.status_code == 200:
                    solutions = resp.json().get("value", [])
                    sentinel_found = any(
                        "sentinel" in s.get("name", "").lower()
                        or "securityinsights" in s.get("name", "").lower()
                        for s in solutions
                    )
                    if sentinel_found:
                        platform_data.access_control.dedicated_security_account = True
                    platform_data.raw_metadata["sentinel_detected"] = sentinel_found
                    logger.info("Azure Sentinel detected: %s", sentinel_found)
                else:
                    logger.warning("Azure Sentinel check returned %s", resp.status_code)
            except Exception as exc:
                logger.error("Azure Sentinel check failed: %s", exc, exc_info=True)

            # ----------------------------------------------------------------
            # Optional: Microsoft Graph — MFA authentication methods policy
            # (Level 1: MFA for Admins / Level 2: Universal MFA)
            #
            # ARM bearer tokens sometimes carry Graph.Policy scope in
            # single-tenant apps. This call gracefully skips (warning only)
            # when the token lacks that permission (HTTP 401/403).
            # ----------------------------------------------------------------
            graph_mfa_url = f"{GRAPH_BASE}/v1.0/policies/authenticationMethodsPolicy"
            self._log(f"GET {graph_mfa_url}")
            try:
                resp = await client.get(
                    graph_mfa_url,
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=10.0,
                )
                if resp.status_code == 200:
                    policy = resp.json()
                    campaign = (
                        policy.get("registrationEnforcement", {})
                              .get("authenticationMethodsRegistrationCampaign", {})
                    )
                    state = campaign.get("state", "disabled")
                    mfa_enforced = state in ("enabled", "default")
                    if mfa_enforced:
                        platform_data.access_control.mfa_enforced_all_pct = 100.0
                        platform_data.access_control.mfa_enforced_admin_pct = 100.0
                    platform_data.raw_metadata["graph_mfa_policy_state"] = state
                    logger.info("Graph MFA policy state: %s (enforced=%s)", state, mfa_enforced)
                elif resp.status_code in (401, 403):
                    logger.warning(
                        "Graph MFA check skipped — ARM token lacks Graph.Policy scope "
                        "(HTTP %s). MFA data sourced from VCS connector only.",
                        resp.status_code,
                    )
                    platform_data.raw_metadata["graph_mfa_policy_state"] = "not_accessible_no_graph_scope"
                else:
                    logger.warning("Graph MFA policy fetch returned %s", resp.status_code)
                    platform_data.raw_metadata["graph_mfa_policy_state"] = "not_accessible"
            except Exception as exc:
                logger.warning("Graph MFA policy check skipped: %s", exc)
                platform_data.raw_metadata["graph_mfa_policy_state"] = "not_accessible"

            # ----------------------------------------------------------------
            # Aggregate raw metadata counts
            # ----------------------------------------------------------------
            platform_data.raw_metadata["vm_count"] = len(vms)
            platform_data.raw_metadata["nsg_count"] = len(nsgs)
            platform_data.raw_metadata["waf_policy_count"] = len(wafs)
            platform_data.raw_metadata["backup_vault_count"] = len(vaults)

        platform_data.cloud_type = "azure"
        platform_data.api_call_log.extend(self._api_call_log)
        return platform_data
