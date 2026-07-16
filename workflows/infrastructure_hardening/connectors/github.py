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
                        # --- Privilege review documentation evidence ---
            access_review_url = (
                f"{GITHUB_API_BASE}/repos/{repository}"
                f"/contents/docs/access-review.md?ref={branch}"
            )
            self._log(f"GET {access_review_url}")
 
            try:
                access_review_resp = await client.get(
                    access_review_url,
                    headers=headers,
                )
 
                if access_review_resp.status_code == 200:
                    platform_data.access_control.privilege_review_documented = True
                    platform_data.raw_metadata["privilege_review_source"] = (
                        "docs/access-review.md"
                    )
                    logger.info(
                        "GitHub privilege review documentation detected"
                    )
                else:
                    platform_data.raw_metadata["privilege_review_source"] = (
                        "not_detected"
                    )
 
            except Exception as exc:
                logger.error(
                    "GitHub privilege review fetch failed: %s",
                    exc,
                    exc_info=True,
                )
 
            # --- HTTPS enforcement documentation evidence ---
            https_doc_url = (
                f"{GITHUB_API_BASE}/repos/{repository}"
                f"/contents/docs/https-enforcement.md?ref={branch}"
            )
            self._log(f"GET {https_doc_url}")
 
            try:
                https_doc_resp = await client.get(
                    https_doc_url,
                    headers=headers,
                )
 
                if https_doc_resp.status_code == 200:
                    platform_data.encryption.edge_https_enforced = True
                    platform_data.raw_metadata["edge_https_source"] = (
                        "docs/https-enforcement.md"
                    )
                    logger.info(
                        "GitHub HTTPS enforcement documentation detected"
                    )
                else:
                    platform_data.raw_metadata["edge_https_source"] = (
                        "not_detected"
                    )
 
            except Exception as exc:
                logger.error(
                    "GitHub HTTPS documentation fetch failed: %s",
                    exc,
                    exc_info=True,
                )

            # --- Virtualized environment documentation evidence ---
            virtualized_doc_url = (
                f"{GITHUB_API_BASE}/repos/{repository}"
                f"/contents/docs/virtualized-environments.md?ref={branch}"
            )
            self._log(f"GET {virtualized_doc_url}")

            try:
                virtualized_doc_resp = await client.get(
                    virtualized_doc_url,
                    headers=headers,
                )

                logger.info(
                    "Virtualized file check | status=%s | body=%s",
                    virtualized_doc_resp.status_code,
                    virtualized_doc_resp.text,
                )

                if virtualized_doc_resp.status_code == 200:
                    platform_data.infrastructure.virtualized_environments = True
                    platform_data.raw_metadata["virtualized_environment_source"] = (
                        "docs/virtualized-environments.md"
                    )
                    logger.info(
                        "GitHub virtualized environment documentation detected"
                    )
                else:
                    platform_data.raw_metadata["virtualized_environment_source"] = (
                        "not_detected"
                    )

            except Exception as exc:
                logger.error(
                    "GitHub virtualized environment documentation fetch failed: %s",
                    exc,
                    exc_info=True,
                )

            # --- Infrastructure as Code (Terraform) evidence ---
            terraform_url = (
                f"{GITHUB_API_BASE}/repos/{repository}"
                f"/contents/infra/logging/main.tf?ref={branch}"
            )
            self._log(f"GET {terraform_url}")

            try:
                terraform_resp = await client.get(
                    terraform_url,
                    headers=headers,
                )

                logger.info(
                    "Terraform file check | status=%s | body=%s",
                    terraform_resp.status_code,
                    terraform_resp.text,
                )

                if terraform_resp.status_code == 200:
                    platform_data.infrastructure.iac_managed = True
                    platform_data.infrastructure.iac_tool = "Terraform"
                    platform_data.raw_metadata["iac_source"] = "infra/logging/main.tf"
                    logger.info("GitHub Terraform infrastructure detected")
                else:
                    platform_data.raw_metadata["iac_source"] = "not_detected"

            except Exception as exc:
                logger.error(
                    "GitHub Terraform detection failed: %s",
                    exc,
                    exc_info=True,
                )
            # --- Automated backup documentation evidence ---
            backup_doc_url = (
                f"{GITHUB_API_BASE}/repos/{repository}"
                f"/contents/docs/backup-policy.md?ref={branch}"
            )
            self._log(f"GET {backup_doc_url}")
 
            try:
                backup_doc_resp = await client.get(
                    backup_doc_url,
                    headers=headers,
                )
 
                if backup_doc_resp.status_code == 200:
                    platform_data.backup.automated_backups_enabled = True
                    platform_data.backup.backup_restore_tested = True
                    platform_data.raw_metadata["backup_policy_source"] = (
                        "docs/backup-policy.md"
                    )
                    logger.info(
                        "GitHub automated backup policy documentation detected"
                    )
                else:
                    platform_data.raw_metadata["backup_policy_source"] = (
                        "not_detected"
                    )
 
            except Exception as exc:
                logger.error(
                    "GitHub backup policy documentation fetch failed: %s",
                    exc,
                    exc_info=True,
                )      
 
        platform_data.vcs_type = "github"
        platform_data.repository = repository
        platform_data.raw_metadata["github_org"] = org_json
        platform_data.raw_metadata["github_branch_protection"] = protection
        platform_data.api_call_log.extend(self._api_call_log)
        return platform_data
