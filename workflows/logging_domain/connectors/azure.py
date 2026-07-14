"""Azure cloud connector — collects centralized logging/monitoring configuration.

Auth: Azure Service Principal (tenant_id, client_id, client_secret, subscription_id),
consistent with existing Azure Service Principal credential handling used
elsewhere in this project.
"""

import httpx

from core.logger import get_logger
from workflows.logging_domain.connectors.base import (
    BaseCloudConnector,
    CloudLoggingData,
    CentralizedLogSystemInfo,
    SecurityEventLoggingInfo,
    LogAnalysisInfo,
)

logger = get_logger(__name__)

AAD_TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
ARM_BASE = "https://management.azure.com"
ARM_API_VERSION = "2021-04-01"
LOG_ANALYTICS_API_VERSION = "2020-08-01"


class AzureCloudConnector(BaseCloudConnector):
    """Collects logging/monitoring configuration from Azure via ARM APIs."""

    async def _get_token(self, client: httpx.AsyncClient) -> str | None:
        tenant_id = self.credentials.get("tenant_id")
        client_id = self.credentials.get("client_id")
        client_secret = self.credentials.get("client_secret")
        if not all([tenant_id, client_id, client_secret]):
            logger.warning("AzureCloudConnector: missing service principal credentials")
            return None

        url = AAD_TOKEN_URL.format(tenant_id=tenant_id)
        self._log(f"POST {url}")
        try:
            resp = await client.post(
                url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "scope": "https://management.azure.com/.default",
                },
            )
            if resp.status_code == 200:
                return resp.json().get("access_token")
            logger.error("AzureCloudConnector token request failed: %s", resp.text)
            return None
        except Exception as exc:
            logger.error("AzureCloudConnector token request error: %s", exc, exc_info=True)
            return None

    async def health_check(self) -> bool:
        async with httpx.AsyncClient(timeout=15) as client:
            token = await self._get_token(client)
            return token is not None

    async def collect(self, **kwargs) -> CloudLoggingData:
        subscription_id = self.credentials.get("subscription_id")
        data = CloudLoggingData(platform_type="azure")

        async with httpx.AsyncClient(timeout=20) as client:
            token = await self._get_token(client)
            if not token:
                data.api_call_log = list(self._api_call_log)
                return data
            headers = {"Authorization": f"Bearer {token}"}

            # 1. Log Analytics workspaces (centralized log system)
            url = (
                f"{ARM_BASE}/subscriptions/{subscription_id}/providers/"
                f"Microsoft.OperationalInsights/workspaces?api-version={LOG_ANALYTICS_API_VERSION}"
            )
            self._log(f"GET {url}")
            try:
                resp = await client.get(url, headers=headers)
                
                print("Workspace Status:", resp.status_code)
                print("Workspace Response:", resp.text)

                if resp.status_code == 200:
                    workspaces = resp.json().get("value", [])
                    if workspaces:
                        ws = workspaces[0]
                        props = ws.get("properties", {})
                        data.centralized_log_system = CentralizedLogSystemInfo(
                            system_name=ws.get("name", "Log Analytics Workspace"),
                            sources_ingesting=[],
                            storage_encrypted=True,  # Log Analytics encrypts at rest by default
                            retention_days=props.get("retentionInDays", 0),
                            integrity_protection_enabled=True,
                        )
                else:
                    logger.error(
                        "Workspace API failed. Status=%s Response=%s",
                        resp.status_code,
                         resp.text,
                    )
            except Exception as exc:
                logger.warning("AzureCloudConnector workspace fetch failed: %s", exc)

            # 2. Diagnostic settings (which resources ship logs centrally)
            url = (
                f"{ARM_BASE}/subscriptions/{subscription_id}/providers/"
                f"Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview"
            )
            self._log(f"GET {url}")
            try:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    settings = resp.json().get("value", [])
                    data.centralized_log_system.sources_ingesting = [
                        s.get("name", "") for s in settings
                    ]
            except Exception as exc:
                logger.warning("AzureCloudConnector diagnostic settings fetch failed: %s", exc)

            # 3. Activity Log / AAD sign-in & audit logs (security events)
            url = (
                f"{ARM_BASE}/subscriptions/{subscription_id}/providers/"
                f"Microsoft.Insights/eventtypes/management/values?api-version=2015-04-01"
            )
            self._log(f"GET {url}")
            try:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    events = resp.json().get("value", [])
                    ops = " ".join(
                        e.get("operationName", {}).get("value", "").lower() for e in events
                    )
                    data.security_events = SecurityEventLoggingInfo(
                        login_logout_logged="signinlogs" in ops or "login" in ops,
                        user_created_logged="createuser" in ops or "adduser" in ops,
                        user_changed_logged="updateuser" in ops,
                        user_deleted_logged="deleteuser" in ops or "removeuser" in ops,
                        correlation_across_sources=len(events) > 0,
                    )
            except Exception as exc:
                logger.warning("AzureCloudConnector activity log fetch failed: %s", exc)

            # 4. Log Analytics query capabilities (analysis + visualization proxy)
            data.log_analysis = LogAnalysisInfo(
                keyword_search_supported=bool(data.centralized_log_system.system_name),
                attack_detection_rules_configured=False,
                real_time_dashboard_available=bool(data.centralized_log_system.system_name),
                gui_search_available=bool(data.centralized_log_system.system_name),
                developer_access_to_app_logs=bool(data.centralized_log_system.sources_ingesting),
            )

        data.api_call_log = list(self._api_call_log)
        return data
