"""GitHub VCS connector — collects logging-configuration signals from a repo."""

import base64
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

    async def collect(self, repository: str, branch: str = "") -> VCSLoggingData:
        token = self.credentials.get("token")
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        data = VCSLoggingData(platform_type="github", repository=repository)

        async with httpx.AsyncClient(timeout=20) as client:
            # 1. Search for logging config files
            for candidate in LOGGING_CONFIG_CANDIDATES:
                if candidate == ".github/workflows":
                    url = f"{GITHUB_API_BASE}/repos/{repository}/contents/.github/workflows"
                    if branch:
                        url += f"?ref={branch}"
                    self._log(f"GET {url}")
                    try:
                        resp = await client.get(url, headers=headers)
                        if resp.status_code == 200 and isinstance(resp.json(), list):
                            data.logging_config_files_found.append(candidate)
                            for item in resp.json():
                                if item.get("type") == "file" and item.get("name", "").endswith((".yml", ".yaml")):
                                    data.log_sources.append(
                                        LogSourceInfo(
                                            name=item.get("name", ""),
                                            path=item.get("path", ""),
                                        )
                                    )
                    except Exception as exc:
                        logger.warning("GitHub contents fetch failed for %s: %s", candidate, exc)
                else:
                    # Try to fetch directly from the branch ref first
                    url = f"{GITHUB_API_BASE}/repos/{repository}/contents/{candidate}"
                    if branch:
                        url += f"?ref={branch}"
                    self._log(f"GET {url}")
                    found_directly = False
                    try:
                        resp = await client.get(url, headers=headers)
                        if resp.status_code == 200:
                            data.logging_config_files_found.append(candidate)
                            data.log_sources.append(
                                LogSourceInfo(
                                    name=candidate,
                                    path=candidate,
                                )
                            )
                            found_directly = True
                    except Exception as exc:
                        logger.warning("GitHub direct fetch failed for %s: %s", candidate, exc)

                    if not found_directly:
                        # Fallback: Search code in repo (usually queries default branch)
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
                if branch:
                    url += f"?ref={branch}"
                self._log(f"GET {url}")
                try:
                    resp = await client.get(url, headers=headers)
                    if resp.status_code == 200:
                        payload = resp.json()
                        content_b64 = payload.get("content", "")
                        if content_b64:
                            raw_bytes = base64.b64decode(content_b64)
                            raw = raw_bytes.decode("utf-8", errors="replace")
                            source.raw_content = raw[:8000]
                            raw_lower = raw.lower()

                            # ---------- Existing Detection ----------

                            source.ships_to_centralized_system = any(
                                kw in raw_lower
                                for kw in [
                                    "splunk",
                                    "elk",
                                    "elasticsearch",
                                    "datadog",
                                    "azure monitor",
                                    "log analytics",
                                ]
                            )

                            source.logs_security_events = any(
                                kw in raw_lower for kw in SECURITY_EVENT_KEYWORDS
                            )

                            source.logs_login_logout = any(
                                kw in raw_lower
                                for kw in ["login", "logout", "signin", "signout"]
                            )

                            source.logs_user_lifecycle_events = any(
                                kw in raw_lower
                                for kw in [
                                    "user_created",
                                    "user_deleted",
                                    "user_changed",
                                    "user.updated",
                                ]
                            )

                            if any(kw in raw_lower for kw in CORRELATION_ID_KEYWORDS):
                                data.correlation_ids_detected = True

                            # ---------- Level 1 ----------

                            source.storage_encrypted = any(
                                kw in raw_lower
                                for kw in [
                                    "encryption",
                                    "aes-256",
                                    "encrypted",
                                ]
                            )

                            source.integrity_protection_enabled = any(
                                kw in raw_lower
                                for kw in [
                                    "tamper_evident_logging",
                                    "write_once_read_many",
                                    "worm",
                                    "immutable",
                                ]
                            )

                            source.alerting_configured = any(
                                    kw in raw_lower
                                    for kw in [
                                        "alert_delivery",
                                        "alerting",
                                        "monitoring",
                                        "incident_response",
                                        "pagerduty",
                                        "azure monitor",
                                        "security-alerts",
                                    ]
                                )  

                            source.incident_analysis_enabled = any(
                                    kw in raw_lower
                                    for kw in [
                                        "incident_analysis",
                                        "root_cause_analysis",
                                        "post_incident_review",
                                        "security incident playbook",
                                        "brute force investigation",
                                        "soc triage",
                                    ]
                                )

                            # ---------- Level 3 ----------

                            source.keyword_search_supported = any(
                                kw in raw_lower
                                for kw in [
                                    "gui_search",
                                    "search",
                                ]
                            )

                            source.attack_detection_enabled = any(
                                kw in raw_lower
                                for kw in [
                                    "attack_detection_rules",
                                    "brute force",
                                    "sql injection",
                                ]
                            )

                            source.gui_search_enabled = any(
                                kw in raw_lower
                                for kw in [
                                    "grafana",
                                    "kibana",
                                    "gui dashboard",
                                ]
                            )

                            source.developer_access_enabled = any(
                                kw in raw_lower
                                for kw in [
                                    "developer_access_policy",
                                    "developers have read-only access",
                                ]
                            )
                            
                except Exception as exc:
                    logger.warning("GitHub content fetch failed for %s: %s", source.path, exc)

            # 3. Check for a documented PII logging policy
            for candidate in PII_POLICY_CANDIDATES:
                url = f"{GITHUB_API_BASE}/repos/{repository}/contents/{candidate}"
                if branch:
                    url += f"?ref={branch}"
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
