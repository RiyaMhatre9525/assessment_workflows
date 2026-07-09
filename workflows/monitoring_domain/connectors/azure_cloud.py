"""
AzureCloudConnector — Cloud connector for monitoring_domain.

Queries Azure Resource Manager (ARM) APIs for live monitoring/alerting/cost
configuration: metric alert rules, cost budgets, diagnostic settings, action
groups, and dashboards. Returns raw ARM JSON responses (never pre-flattened
booleans) so the LLM can reason over actual configuration.

Auth note: ARM access tokens are short-lived (~1 hour). Production use
requires a Service Principal via the client-credentials flow, so
credentials must include tenant_id, client_id, and client_secret
long-term (not a raw bearer token).
"""

import httpx

from core.logger import get_logger
from .base import BasePlatformConnector, CloudMonitoringData

logger = get_logger(__name__)

ARM_BASE = "https://management.azure.com"
ARM_API_VERSION_INSIGHTS = "2023-01-01"
ARM_API_VERSION_CONSUMPTION = "2023-05-01"
ARM_API_VERSION_DIAGNOSTICS = "2021-05-01-preview"
ARM_API_VERSION_DASHBOARD = "2022-08-01"


class AzureCloudConnector(BasePlatformConnector):
    def __init__(self, credentials: dict) -> None:
        super().__init__(credentials)
        self.tenant_id = credentials.get("tenant_id", "")
        self.client_id = credentials.get("client_id", "")
        self.client_secret = credentials.get("client_secret", "")
        self.subscription_id = credentials.get("subscription_id", "")
        self._token: str = ""

    async def _get_token(self, client: httpx.AsyncClient) -> str:
        if self._token:
            return self._token
        url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        self._log(f"POST {url}")
        payload = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": "https://management.azure.com/.default",
        }
        try:
            resp = await client.post(url, data=payload)
            resp.raise_for_status()
            self._token = resp.json()["access_token"]
            return self._token
        except httpx.HTTPStatusError as exc:
            logger.error("OAuth token request failed with status %s: %s", exc.response.status_code, exc.response.text)
            raise
        except Exception as exc:
            logger.error("OAuth token request failed: %s", exc)
            raise

    def _headers(self, token: str) -> dict:
        return {"Authorization": f"Bearer {token}"}

    async def health_check(self) -> bool:
        try:
            logger.info("Starting Azure Cloud health check: tenant_id=%s, client_id=%s, subscription_id=%s",
                        self.tenant_id, self.client_id, self.subscription_id)
            async with httpx.AsyncClient(timeout=15) as client:
                token = await self._get_token(client)
                url = f"{ARM_BASE}/subscriptions/{self.subscription_id}?api-version=2022-12-01"
                self._log(f"GET {url}")
                resp = await client.get(url, headers=self._headers(token))
                if resp.status_code != 200:
                    logger.error("Subscription health check failed with status %s: %s", resp.status_code, resp.text)
                return resp.status_code == 200
        except Exception as exc:
            logger.error("Azure Cloud health_check failed: %s", exc, exc_info=True)
            return False

    async def collect(self, repository: str) -> CloudMonitoringData:
        # `repository` is unused for cloud collection (kept for ABC signature
        # parity); scope is the subscription configured in credentials.
        data = CloudMonitoringData(platform_type="azure", subscription_id=self.subscription_id)

        async with httpx.AsyncClient(timeout=25) as client:
            try:
                token = await self._get_token(client)
            except Exception as exc:
                logger.error("Azure token acquisition failed: %s", exc, exc_info=True)
                data.api_call_log = list(self._api_call_log)
                return data

            headers = self._headers(token)
            sub = self.subscription_id

            # Metric alert rules
            url = f"{ARM_BASE}/subscriptions/{sub}/providers/Microsoft.Insights/metricAlerts?api-version={ARM_API_VERSION_INSIGHTS}"
            self._log(f"GET {url}")
            try:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    data.metric_alert_rules = resp.json().get("value", [])
            except Exception as exc:
                logger.warning("Failed to fetch metric alert rules: %s", exc)

            # Action groups (role-based incident routing)
            url = f"{ARM_BASE}/subscriptions/{sub}/providers/Microsoft.Insights/actionGroups?api-version={ARM_API_VERSION_INSIGHTS}"
            self._log(f"GET {url}")
            try:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    data.action_groups = resp.json().get("value", [])
            except Exception as exc:
                logger.warning("Failed to fetch action groups: %s", exc)

            # Cost budgets
            url = f"{ARM_BASE}/subscriptions/{sub}/providers/Microsoft.Consumption/budgets?api-version={ARM_API_VERSION_CONSUMPTION}"
            self._log(f"GET {url}")
            try:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    data.cost_budgets = resp.json().get("value", [])
            except Exception as exc:
                logger.warning("Failed to fetch cost budgets: %s", exc)

            # Diagnostic settings (system event auditing) — subscription-level
            url = f"{ARM_BASE}/subscriptions/{sub}/providers/Microsoft.Insights/diagnosticSettings?api-version={ARM_API_VERSION_DIAGNOSTICS}"
            self._log(f"GET {url}")
            try:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    data.diagnostic_settings = resp.json().get("value", [])
            except Exception as exc:
                logger.warning("Failed to fetch diagnostic settings: %s", exc)

            # Dashboards (internal security / metric visualization)
            url = f"{ARM_BASE}/subscriptions/{sub}/providers/Microsoft.Portal/dashboards?api-version={ARM_API_VERSION_DASHBOARD}"
            self._log(f"GET {url}")
            try:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    data.dashboards = resp.json().get("value", [])
            except Exception as exc:
                logger.warning("Failed to fetch dashboards: %s", exc)

            # Security-relevant metric sources (Defender for Cloud assessments,
            # used to evidence patch/vulnerability/anti-virus coverage metrics)
            url = f"{ARM_BASE}/subscriptions/{sub}/providers/Microsoft.Security/assessments?api-version=2021-06-01"
            self._log(f"GET {url}")
            try:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    data.security_metric_sources = resp.json().get("value", [])
            except Exception as exc:
                logger.warning("Failed to fetch security assessments: %s", exc)

        data.api_call_log = list(self._api_call_log)
        return data
