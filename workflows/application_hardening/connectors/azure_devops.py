"""
Azure DevOps VCS connector for application_hardening.

Uses the Azure DevOps REST API to detect frontend frameworks, output-encoding
libraries, CSP configuration, and parametrized-query usage as static,
code-level signals feeding the ASVS code-side compliance estimate.
"""
import base64

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


class AzureDevOpsConnector(BasePlatformConnector):
    """Collects code-level application security signals from Azure DevOps.

    Expects scope in 'organization/project/repository' form and credentials
    containing a Personal Access Token under 'token'.
    """

    def _auth_header(self) -> dict:
        token = self.credentials.get("token", "")
        b64 = base64.b64encode(f":{token}".encode()).decode()
        return {"Authorization": f"Basic {b64}"}

    async def health_check(self) -> bool:
        org = self.credentials.get("organization")
        if not org or not self.credentials.get("token"):
            return False
        url = f"https://dev.azure.com/{org}/_apis/projects?api-version=7.1"
        self._log(f"GET {url}")
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(url, headers=self._auth_header())
            return resp.status_code == 200
        except Exception as exc:
            logger.error("Azure DevOps health_check failed: %s", exc, exc_info=True)
            return False

    async def collect(self, scope: str) -> VcsSecurityData:
        """scope is 'organization/project/repository'."""
        org, project, repo = (scope.split("/", 2) + ["", ""])[:3]
        data = VcsSecurityData(vcs_platform_type="azure_devops", repository=scope)
        headers = self._auth_header()

        async with httpx.AsyncClient(timeout=20) as client:
            # 1. Fetch package.json manifest for framework/ORM/encoding detection.
            item_url = (
                f"https://dev.azure.com/{org}/{project}/_apis/git/repositories/{repo}/items"
            )
            self._log(f"GET {item_url}?path=/package.json")
            manifest_text = ""
            try:
                resp = await client.get(
                    item_url,
                    headers=headers,
                    params={"path": "/package.json", "api-version": "7.1"},
                )
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

            # 2. Search code for CSP configuration.
            search_url = f"https://almsearch.dev.azure.com/{org}/{project}/_apis/search/codesearchresults"
            self._log(f"POST {search_url} (query=Content-Security-Policy)")
            try:
                resp = await client.post(
                    search_url,
                    headers=headers,
                    params={"api-version": "7.1"},
                    json={"searchText": "Content-Security-Policy", "$top": 1},
                )
                if resp.status_code == 200:
                    data.output_encoding.csp_header_present = resp.json().get("count", 0) > 0
            except Exception as exc:
                logger.warning("CSP search failed for %s: %s", scope, exc)

            # 3. Search for ORM usage vs raw query concatenation.
            orm_hit = False
            raw_hit = False
            for marker in ORM_MARKERS:
                self._log(f"POST {search_url} (query={marker})")
                try:
                    resp = await client.post(
                        search_url,
                        headers=headers,
                        params={"api-version": "7.1"},
                        json={"searchText": marker, "$top": 1},
                    )
                    if resp.status_code == 200 and resp.json().get("count", 0) > 0:
                        orm_hit = True
                        data.input_validation.orm_tool_detected = marker
                        break
                except Exception as exc:
                    logger.warning("ORM marker search failed for %s: %s", scope, exc)

            for marker in RAW_QUERY_MARKERS:
                self._log(f"POST {search_url} (query={marker})")
                try:
                    resp = await client.post(
                        search_url,
                        headers=headers,
                        params={"api-version": "7.1"},
                        json={"searchText": marker, "$top": 1},
                    )
                    if resp.status_code == 200 and resp.json().get("count", 0) > 0:
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
