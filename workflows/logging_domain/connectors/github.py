"""GitHub VCS connector — collects logging-configuration signals from a repo."""

import httpx

from core.logger import get_logger
from workflows.logging_domain.connectors.base import (
    BaseVCSConnector,
    VCSLoggingData,
    LogSourceInfo,
)

logger = get_logger(__name__)

GITHUB_API_BASE = "https://api.github.com"

# File paths / keywords we look for when scanning a repo for logging config.
LOGGING_CONFIG_CANDIDATES = [
    ".github/workflows",
    "logging.yaml",
    "logging.yml",
    "log4j.xml",
    "log4j2.xml",
    "logback.xml",
    "fluentd.conf",
    "fluent-bit.conf",
    "otel-collector-config.yaml",
    "filebeat.yml",
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


class GitHubVCSConnector(BaseVCSConnector):
    """Collects logging-relevant signals from a GitHub repository."""

    async def health_check(self) -> bool:
        token = self.credentials.get("token")
        if not token:
            logger.warning("GitHubVCSConnector: missing token in credentials")
            return False
        url = f"{GITHUB_API_BASE}/user"
        self._log(f"GET {url}")
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    url, headers={"Authorization": f"Bearer {token}"}
                )
                return resp.status_code == 200
        except Exception as exc:
            logger.error("GitHubVCSConnector health_check failed: %s", exc, exc_info=True)
            return False

    async def collect(self, repository: str) -> VCSLoggingData:
        token = self.credentials.get("token")
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        data = VCSLoggingData(platform_type="github", repository=repository)

        async with httpx.AsyncClient(timeout=20) as client:
            # 1. Search for logging config files
            for candidate in LOGGING_CONFIG_CANDIDATES:
                url = f"{GITHUB_API_BASE}/search/code"
                params = {"q": f"filename:{candidate} repo:{repository}"}
                self._log(f"GET {url} q={params['q']}")
                try:
                    resp = await client.get(url, headers=headers, params=params)
                    if resp.status_code == 200 and resp.json().get("total_count", 0) > 0:
                        data.logging_config_files_found.append(candidate)
                        for item in resp.json().get("items", [])[:5]:
                            data.log_sources.append(
                                LogSourceInfo(
                                    name=item.get("name", candidate),
                                    path=item.get("path", candidate),
                                )
                            )
                except Exception as exc:
                    logger.warning("GitHub search failed for %s: %s", candidate, exc)

            # 2. Scan CI workflow / config content for security-event & correlation signals
            for source in data.log_sources:
                url = f"{GITHUB_API_BASE}/repos/{repository}/contents/{source.path}"
                self._log(f"GET {url}")
                try:
                    resp = await client.get(url, headers=headers)
                    if resp.status_code == 200:
                        raw = resp.text.lower()
                        source.raw_content = resp.text[:2000]
                        source.ships_to_centralized_system = any(
                            kw in raw for kw in ["splunk", "elk", "elasticsearch",
                                                  "datadog", "azure monitor", "log analytics"]
                        )
                        source.logs_security_events = any(kw in raw for kw in SECURITY_EVENT_KEYWORDS)
                        source.logs_login_logout = any(kw in raw for kw in ["login", "logout", "signin", "signout"])
                        source.logs_user_lifecycle_events = any(
                            kw in raw for kw in ["user_created", "user_deleted", "user_changed", "user.updated"]
                        )
                        if any(kw in raw for kw in CORRELATION_ID_KEYWORDS):
                            data.correlation_ids_detected = True
                except Exception as exc:
                    logger.warning("GitHub content fetch failed for %s: %s", source.path, exc)

            # 3. Check for a documented PII logging policy
            for candidate in PII_POLICY_CANDIDATES:
                url = f"{GITHUB_API_BASE}/repos/{repository}/contents/{candidate}"
                self._log(f"GET {url}")
                try:
                    resp = await client.get(url, headers=headers)
                    if resp.status_code == 200:
                        data.pii_logging_policy_doc_found = True
                        break
                except Exception as exc:
                    logger.warning("GitHub PII policy check failed for %s: %s", candidate, exc)

        data.api_call_log = list(self._api_call_log)
        return data
