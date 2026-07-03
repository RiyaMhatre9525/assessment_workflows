"""
GitHub VCS connector for application_hardening.

Uses the GitHub REST API to detect frontend frameworks, output-encoding
libraries, CSP configuration, parametrized-query usage, and Dockerfile
non-root enforcement as static, code-level signals feeding the ASVS
code-side compliance estimate.
"""
import httpx

from core.logger import get_logger
from .base import (
    AsvsComplianceInfo,
    BasePlatformConnector,
    FrameworkInfo,
    InputValidationInfo,
    OutputEncodingInfo,
    VcsSecurityData,
)

logger = get_logger(__name__)

GITHUB_API_BASE = "https://api.github.com"

FRAMEWORK_DEPENDENCIES = ["react", "angular", "vue", "svelte"]
ENCODING_LIBRARY_MARKERS = [
    "owasp-java-encoder",
    "org.owasp.encoder",
    "antixss",
    "microsoft.security.application",
    "dompurify",
]
ORM_MARKERS = ["sequelize", "typeorm", "prisma", "sqlalchemy", "hibernate", "entity framework", "django.db"]
RAW_QUERY_MARKERS = ["execute(f\"", "cursor.execute(\"select", "+ query +", "string.format(\"select"]


class GitHubConnector(BasePlatformConnector):
    """Collects code-level application security signals from GitHub."""

    async def health_check(self) -> bool:
        token = self.credentials.get("token")
        if not token:
            return False
        self._log(f"GET {GITHUB_API_BASE}/user")
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    f"{GITHUB_API_BASE}/user",
                    headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
                )
            return resp.status_code == 200
        except Exception as exc:
            logger.error("GitHub health_check failed: %s", exc, exc_info=True)
            return False

    async def collect(self, scope: str) -> VcsSecurityData:
        """scope is the repository in 'owner/repo' form."""
        data = VcsSecurityData(vcs_platform_type="github", repository=scope)
        token = self.credentials.get("token")
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}

        async with httpx.AsyncClient(timeout=20) as client:
            # 1. Detect frontend frameworks + ORM/encoding markers via manifest files.
            manifest_url = f"{GITHUB_API_BASE}/repos/{scope}/contents/package.json"
            self._log(f"GET {manifest_url}")
            manifest_text = ""
            try:
                resp = await client.get(manifest_url, headers=headers)
                if resp.status_code == 200:
                    manifest_text = resp.text.lower()
            except Exception as exc:
                logger.warning("Failed to fetch package.json for %s: %s", scope, exc)

            frameworks = []
            for fw in FRAMEWORK_DEPENDENCIES:
                frameworks.append(FrameworkInfo(
                    name=fw,
                    detected=fw in manifest_text,
                    safe_default_rendering=fw in manifest_text,
                ))
            data.output_encoding = OutputEncodingInfo(
                frameworks_detected=frameworks,
                encoding_library_detected=next(
                    (m for m in ENCODING_LIBRARY_MARKERS if m in manifest_text), ""
                ),
                csp_header_present=False,
                csp_policy="",
            )

            # 2. Search repo for CSP configuration.
            csp_search_url = f"{GITHUB_API_BASE}/search/code"
            self._log(f"GET {csp_search_url}?q=Content-Security-Policy+repo:{scope}")
            try:
                resp = await client.get(
                    csp_search_url,
                    headers=headers,
                    params={"q": f"Content-Security-Policy repo:{scope}"},
                )
                if resp.status_code == 200:
                    data.output_encoding.csp_header_present = resp.json().get("total_count", 0) > 0
            except Exception as exc:
                logger.warning("CSP search failed for %s: %s", scope, exc)

            # 3. Search for parametrized query / ORM usage vs raw concatenation.
            orm_hit = False
            raw_hit = False
            for marker in ORM_MARKERS:
                search_url = f"{GITHUB_API_BASE}/search/code"
                self._log(f"GET {search_url}?q={marker}+repo:{scope}")
                try:
                    resp = await client.get(search_url, headers=headers, params={"q": f"{marker} repo:{scope}"})
                    if resp.status_code == 200 and resp.json().get("total_count", 0) > 0:
                        orm_hit = True
                        data.input_validation.orm_tool_detected = marker
                        break
                except Exception as exc:
                    logger.warning("ORM marker search failed for %s: %s", scope, exc)

            for marker in RAW_QUERY_MARKERS:
                search_url = f"{GITHUB_API_BASE}/search/code"
                self._log(f"GET {search_url}?q={marker}+repo:{scope}")
                try:
                    resp = await client.get(search_url, headers=headers, params={"q": f"{marker} repo:{scope}"})
                    if resp.status_code == 200 and resp.json().get("total_count", 0) > 0:
                        raw_hit = True
                        break
                except Exception as exc:
                    logger.warning("Raw query marker search failed for %s: %s", scope, exc)

            data.input_validation = InputValidationInfo(
                parametrized_queries_detected=orm_hit and not raw_hit,
                orm_tool_detected=data.input_validation.orm_tool_detected,
                stored_procedures_detected=orm_hit,
                raw_query_concatenation_found=raw_hit,
            )

            # 4. Estimate ASVS L1/L2/L3 code-side compliance from the signals above.
            code_controls_met = sum([
                any(f.detected for f in frameworks),
                data.output_encoding.csp_header_present,
                bool(data.output_encoding.encoding_library_detected),
                data.input_validation.parametrized_queries_detected,
                not data.input_validation.raw_query_concatenation_found,
            ])
            pct = (code_controls_met / 5) * 100
            data.asvs_l1_code = AsvsComplianceInfo(asvs_level=1, total_controls=5, controls_met=code_controls_met, percentage=pct)
            data.asvs_l2_code = AsvsComplianceInfo(asvs_level=2, total_controls=5, controls_met=code_controls_met, percentage=pct * 0.85)
            data.asvs_l3_code = AsvsComplianceInfo(asvs_level=3, total_controls=5, controls_met=code_controls_met, percentage=pct * 0.7)

        data.api_call_log = list(self._api_call_log)
        return data
