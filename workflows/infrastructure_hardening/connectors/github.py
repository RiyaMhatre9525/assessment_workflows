"""
workflows/infrastructure_hardening/connectors/github.py

GitHub VCS connector. Collects VCS-observable evidence relevant to
Level 1-3 access-control and RBAC criteria:
  - Organization-wide MFA (two-factor) enforcement
  - Org admin count (proxy for "Simple Access Control" / admin count <=5)
  - Branch protection required-reviews (proxy for RBAC signal)
"""

from __future__ import annotations

import httpx

from core.logger import get_logger
from workflows.infrastructure_hardening.connectors.base import (
    BaseVCSConnector,
    PlatformData,
)

logger = get_logger(__name__)

GITHUB_API_BASE = "https://api.github.com"


class GitHubConnector(BaseVCSConnector):

    async def health_check(self) -> bool:
        token = self.credentials.get("token", "")
        url = f"{GITHUB_API_BASE}/user"
        self._log(f"GET {url}")
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    url,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Accept": "application/vnd.github+json",
                    },
                )
                return resp.status_code == 200
        except Exception as exc:
            logger.error("GitHub health_check failed: %s", exc, exc_info=True)
            return False

    async def collect(self, repository: str, platform_data: PlatformData) -> PlatformData:
        token = self.credentials.get("token", "")
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
        }
        org = repository.split("/")[0] if "/" in repository else repository
        branch = self.credentials.get("branch", "main")

        async with httpx.AsyncClient(timeout=20.0) as client:
            # --- Org-wide MFA enforcement ---
            org_url = f"{GITHUB_API_BASE}/orgs/{org}"
            self._log(f"GET {org_url}")
            org_json: dict = {}
            try:
                org_resp = await client.get(org_url, headers=headers)
                if org_resp.status_code == 200:
                    org_json = org_resp.json()
                else:
                    logger.warning("GitHub org fetch returned %s", org_resp.status_code)
            except Exception as exc:
                logger.error("GitHub org fetch failed: %s", exc, exc_info=True)

            mfa_required = bool(org_json.get("two_factor_requirement_enabled", False))
            platform_data.access_control.mfa_enforced_admin_pct = 100.0 if mfa_required else 0.0
            platform_data.access_control.mfa_enforced_all_pct = 100.0 if mfa_required else 0.0

            # --- Org admin count (proxy for admin count <=5 criterion) ---
            members_url = f"{GITHUB_API_BASE}/orgs/{org}/members?role=admin&per_page=100"
            self._log(f"GET {members_url}")
            admins: list = []
            try:
                members_resp = await client.get(members_url, headers=headers)
                if members_resp.status_code == 200:
                    admins = members_resp.json()
                else:
                    logger.warning("GitHub admins fetch returned %s", members_resp.status_code)
            except Exception as exc:
                logger.error("GitHub admins fetch failed: %s", exc, exc_info=True)
            if isinstance(admins, list):
                platform_data.access_control.admin_count = len(admins)

            # --- Branch protection (RBAC + immutable-history signal) ---
            branch_url = f"{GITHUB_API_BASE}/repos/{repository}/branches/{branch}/protection"
            self._log(f"GET {branch_url}")
            protection: dict = {}
            try:
                branch_resp = await client.get(branch_url, headers=headers)
                if branch_resp.status_code == 200:
                    protection = branch_resp.json()
                else:
                    logger.warning("GitHub branch protection fetch returned %s", branch_resp.status_code)
            except Exception as exc:
                logger.error("GitHub branch protection fetch failed: %s", exc, exc_info=True)

            platform_data.access_control.rbac_enabled = bool(
                protection.get("required_pull_request_reviews")
            )

        platform_data.vcs_type = "github"
        platform_data.repository = repository
        platform_data.raw_metadata["github_org"] = org_json
        platform_data.raw_metadata["github_branch_protection"] = protection
        platform_data.api_call_log.extend(self._api_call_log)
        return platform_data
