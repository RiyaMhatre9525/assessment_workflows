"""Azure DevOps VCS connector — collects logging-configuration signals from a repo."""

import base64

import httpx

from core.logger import get_logger
from workflows.logging_domain.connectors.base import (
    BaseVCSConnector,
    VCSLoggingData,
    LogSourceInfo,
)

logger = get_logger(__name__)

AZDO_API_BASE = "https://dev.azure.com"
API_VERSION = "7.1"

LOGGING_CONFIG_CANDIDATES = [
    "azure-pipelines.yml",
    "logging.yaml",
    "logging.yml",
    "log4j2.xml",
    "logback.xml",
    "appsettings.json",
]

SECURITY_EVENT_KEYWORDS = [
    "login", "logout", "signin", "signout",
    "user_created", "user.created", "useradded",
    "user_deleted", "user.deleted", "userremoved",
    "user_changed", "user.updated", "role_changed",
]

CORRELATION_ID_KEYWORDS = ["correlation_id", "trace_id", "x-request-id", "traceparent"]

PII_POLICY_CANDIDATES = [
    "PII_POLICY.md",
    "docs/pii-logging-policy.md",
    "docs/privacy/logging.md",
    "PRIVACY.md",
]


def _auth_header(pat: str) -> dict:
    token = base64.b64encode(f":{pat}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


class AzureDevOpsVCSConnector(BaseVCSConnector):
    """Collects logging-relevant signals from an Azure DevOps repository.

    `repository` is expected as "org/project/repo".
    """

    async def health_check(self) -> bool:
        pat = self.credentials.get("pat")
        if not pat:
            logger.warning("AzureDevOpsVCSConnector: missing pat in credentials")
            return False
        try:
            org = self.credentials.get("organization", "")
            url = f"{AZDO_API_BASE}/{org}/_apis/projects?api-version={API_VERSION}"
            self._log(f"GET {url}")
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(url, headers=_auth_header(pat))
                return resp.status_code == 200
        except Exception as exc:
            logger.error("AzureDevOpsVCSConnector health_check failed: %s", exc, exc_info=True)
            return False

    async def collect(self, repository: str) -> VCSLoggingData:
        pat = self.credentials.get("pat", "")
        headers = _auth_header(pat) if pat else {}
        parts = repository.split("/")
        org, project, repo = (parts + ["", "", ""])[:3]
        data = VCSLoggingData(platform_type="azure_devops", repository=repository)

        async with httpx.AsyncClient(timeout=20) as client:
            for candidate in LOGGING_CONFIG_CANDIDATES:
                url = (
                    f"{AZDO_API_BASE}/{org}/{project}/_apis/git/repositories/{repo}/items"
                    f"?path=/{candidate}&api-version={API_VERSION}"
                )
                self._log(f"GET {url}")
                try:
                    resp = await client.get(url, headers=headers)
                    if resp.status_code == 200:
                        data.logging_config_files_found.append(candidate)
                        raw_text = resp.text
                        source = LogSourceInfo(name=candidate, path=candidate, raw_content=raw_text[:2000])
                        raw_lower = raw_text.lower()
                        source.ships_to_centralized_system = any(
                            kw in raw_lower for kw in ["splunk", "elk", "elasticsearch",
                                                        "datadog", "azure monitor", "log analytics"]
                        )
                        source.logs_security_events = any(kw in raw_lower for kw in SECURITY_EVENT_KEYWORDS)
                        source.logs_login_logout = any(
                            kw in raw_lower for kw in ["login", "logout", "signin", "signout"]
                        )
                        source.logs_user_lifecycle_events = any(
                            kw in raw_lower for kw in ["user_created", "user_deleted", "user_changed", "user.updated"]
                        )
                        if any(kw in raw_lower for kw in CORRELATION_ID_KEYWORDS):
                            data.correlation_ids_detected = True
                        data.log_sources.append(source)
                except Exception as exc:
                    logger.warning("Azure DevOps item fetch failed for %s: %s", candidate, exc)

            for candidate in PII_POLICY_CANDIDATES:
                url = (
                    f"{AZDO_API_BASE}/{org}/{project}/_apis/git/repositories/{repo}/items"
                    f"?path=/{candidate}&api-version={API_VERSION}"
                )
                self._log(f"GET {url}")
                try:
                    resp = await client.get(url, headers=headers)
                    if resp.status_code == 200:
                        data.pii_logging_policy_doc_found = True
                        break
                except Exception as exc:
                    logger.warning("Azure DevOps PII policy check failed for %s: %s", candidate, exc)

        data.api_call_log = list(self._api_call_log)
        return data
