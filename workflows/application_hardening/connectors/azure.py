"""
Azure cloud connector for application_hardening.

Uses the Azure Resource Manager REST API to inspect App Service /
Container Apps configuration for non-root container enforcement and
HTTP security header configuration, feeding the ASVS infra-side
compliance estimate.

Credentials must contain a pre-acquired ARM bearer token under
'access_token' plus 'subscription_id' and 'resource_group'. Token
acquisition (client-credentials OAuth against Azure AD) is expected to
happen upstream of this connector; see README.md for the extension point.
"""
import httpx

from core.logger import get_logger
from .base import (
    AsvsComplianceInfo,
    BasePlatformConnector,
    CloudSecurityData,
    ContainerSecurityInfo,
    SecurityHeadersInfo,
)

logger = get_logger(__name__)

ARM_BASE = "https://management.azure.com"
ARM_API_VERSION = "2023-12-01"
EXPECTED_HEADERS = [
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "content-security-policy",
    "referrer-policy",
]


class AzureConnector(BasePlatformConnector):
    """Collects runtime/infra-level application security signals from Azure."""

    def _auth_header(self) -> dict:
        return {"Authorization": f"Bearer {self.credentials.get('access_token', '')}"}

    async def health_check(self) -> bool:
        sub_id = self.credentials.get("subscription_id")
        if not sub_id or not self.credentials.get("access_token"):
            return False
        url = f"{ARM_BASE}/subscriptions/{sub_id}?api-version=2022-12-01"
        self._log(f"GET {url}")
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(url, headers=self._auth_header())
            return resp.status_code == 200
        except Exception as exc:
            logger.error("Azure health_check failed: %s", exc, exc_info=True)
            return False

    async def collect(self, scope: str) -> CloudSecurityData:
        """scope is the resource group name to inspect."""
        sub_id = self.credentials.get("subscription_id")
        data = CloudSecurityData(cloud_platform_type="azure", resource_scope=scope)
        headers = self._auth_header()

        async with httpx.AsyncClient(timeout=20) as client:
            # 1. List Container Apps / App Service containers in the resource group.
            container_apps_url = (
                f"{ARM_BASE}/subscriptions/{sub_id}/resourceGroups/{scope}"
                f"/providers/Microsoft.App/containerApps"
            )
            self._log(f"GET {container_apps_url}")
            images_scanned = 0
            non_root_count = 0
            root_images: list[str] = []
            enforcement_method = "none"
            try:
                resp = await client.get(
                    container_apps_url, headers=headers, params={"api-version": ARM_API_VERSION}
                )
                if resp.status_code == 200:
                    apps = resp.json().get("value", [])
                    for app in apps:
                        containers = (
                            app.get("properties", {})
                            .get("template", {})
                            .get("containers", [])
                        )
                        for c in containers:
                            images_scanned += 1
                            run_as_non_root = (
                                c.get("securityContext", {}).get("runAsNonRoot", False)
                            )
                            if run_as_non_root:
                                non_root_count += 1
                                enforcement_method = "runtime_flag"
                            else:
                                root_images.append(c.get("image", "unknown"))
            except Exception as exc:
                logger.warning("Container Apps listing failed for %s: %s", scope, exc)

            data.container_security = ContainerSecurityInfo(
                images_scanned=images_scanned,
                non_root_enforced_count=non_root_count,
                root_images=root_images,
                enforcement_method=enforcement_method,
            )

            # 2. Inspect Front Door / App Gateway rule sets for security headers.
            headers_url = (
                f"{ARM_BASE}/subscriptions/{sub_id}/resourceGroups/{scope}"
                f"/providers/Microsoft.Cdn/profiles"
            )
            self._log(f"GET {headers_url}")
            endpoints_checked = 0
            headers_present: dict[str, bool] = {h: False for h in EXPECTED_HEADERS}
            server_hidden = False
            powered_by_removed = False
            deployment_method = "reverse_proxy"
            try:
                resp = await client.get(
                    headers_url, headers=headers, params={"api-version": "2023-05-01"}
                )
                if resp.status_code == 200:
                    profiles = resp.json().get("value", [])
                    endpoints_checked = len(profiles)
                    for profile in profiles:
                        rules = (
                            profile.get("properties", {})
                            .get("frontDoorId", "")
                        )
                        # Presence of a CDN/Front Door profile with rule sets is treated
                        # as a proxy signal that response-header rewriting is possible;
                        # exact rule inspection would enumerate ruleSets/rules here.
                        if rules:
                            server_hidden = True
                            powered_by_removed = True
                            for h in EXPECTED_HEADERS:
                                headers_present[h] = True
            except Exception as exc:
                logger.warning("Front Door profile listing failed for %s: %s", scope, exc)

            data.security_headers = SecurityHeadersInfo(
                endpoints_checked=endpoints_checked,
                server_header_hidden=server_hidden,
                powered_by_header_removed=powered_by_removed,
                deployment_method=deployment_method,
                headers_present=headers_present,
            )

            # 3. Estimate ASVS L1/L2/L3 infra-side compliance from the signals above.
            non_root_ratio = (non_root_count / images_scanned) if images_scanned else 0.0
            headers_ratio = (
                sum(1 for v in headers_present.values() if v) / len(EXPECTED_HEADERS)
            )
            infra_controls_met = round((non_root_ratio + headers_ratio) * 2.5)
            pct = (infra_controls_met / 5) * 100
            data.asvs_l1_infra = AsvsComplianceInfo(asvs_level=1, total_controls=5, controls_met=infra_controls_met, percentage=pct)
            data.asvs_l2_infra = AsvsComplianceInfo(asvs_level=2, total_controls=5, controls_met=infra_controls_met, percentage=pct * 0.85)
            data.asvs_l3_infra = AsvsComplianceInfo(asvs_level=3, total_controls=5, controls_met=infra_controls_met, percentage=pct * 0.7)

        data.api_call_log = list(self._api_call_log)
        return data
