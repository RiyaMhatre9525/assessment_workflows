"""
Azure DevOps Git connector for the Static_Depth_for_Infrastructure workflow.

Collects pipeline (YAML) definitions and a repository file listing from
Azure DevOps, then scans both against a canonical set of keyword/filename
signals (one group per maturity criterion) to build provider-agnostic
evidence for the LLM-driven assessment nodes in nodes.py.

This connector ONLY collects evidence — it never decides pass/fail. That
decision is made by the assessment nodes, which read the
InfrastructureEvidence this connector returns (cross-checked against
detected_signals as an evidence floor — see nodes.py).
"""

from __future__ import annotations

import base64

import httpx

from core.logger import get_logger
from workflows.Static_Depth_for_Infrastructure.connectors.base import (
    BaseSourceControlConnector,
    InfrastructureEvidence,
    PipelineDefinition,
)

logger = get_logger(__name__)

API_VERSION = "7.1"
MAX_FILES = 500

# ---------------------------------------------------------------------------
# Canonical criterion -> keyword/filename signals.
# Keys MUST match config.LEVEL_CRITERIA_NAMES exactly.
# Matching is case-insensitive substring search across combined pipeline
# YAML content + the flattened repository file path listing.
# ---------------------------------------------------------------------------
SIGNAL_KEYWORDS: dict[str, list[str]] = {
    "Test for Stored Secrets in Build Artifacts": [
        "trivy image", "docker scout", "gitleaks --source .", "grype", "container secret scan",
        "secret scan image",
    ],
    "Test for Stored Secrets in Source Code": [
        "gitleaks", "trufflehog", "detect-secrets", "git-secrets", "secret scanning",
        "advanced security",
    ],
    "Test Cluster Deployment Resources": [
        "kube-bench", "kubesec", "checkov", "polaris", "kube-score", "helm lint",
    ],
    "Test Image Lifetime": [
        "image lifetime", "image age policy", "stale image", "max image age", "image freshness",
    ],
    "Test Virtualized Environments": [
        "docker bench", "cis benchmark", "container runtime security", "vm security baseline", "inspec",
    ],
    "Test Cloud Configuration": [
        "azure security benchmark", "defender for cloud", "azure policy", "security center",
        "cis azure benchmark", "cloud security posture",
    ],
    "Test Definition of Virtualized Environments": [
        "checkov", "tfsec", "terrascan", "arm-ttk", "psrule", "terraform", "bicep", "iac scan",
    ],
    "Test for Malware": [
        "clamav", "malware scan", "defender malware", "virus scan", "microsoft defender for containers",
    ],
    "Test for New Image Version": [
        "renovate", "watchtower", "base image update", "image freshness check", "docker image update check",
    ],
    "Correlate Known Vulnerabilities with New Image Versions": [
        "vulnerability correlation", "upgrade mitigates", "patch impact analysis", "cve remediation via upgrade",
    ],
    "Software Composition Analysis (SCA)": [
        "trivy fs", "grype", "anchore", "snyk container", "syft", "dependency-check",
    ],
    "Test Infrastructure Components for Known Vulnerabilities": [
        "cve scan", "security advisories", "trivy image", "qualys", "nessus",
        "missing security updates", "vulnerability scan",
    ],
}

IAC_FILE_EXTENSIONS = [".tf", ".bicep", "arm-template", ".yaml", ".yml"]


def _detect_signals(text: str, file_list: list[str]) -> dict[str, list[str]]:
    lowered_text = text.lower()
    lowered_files = [f.lower() for f in file_list]
    signals: dict[str, list[str]] = {}

    for criterion, keywords in SIGNAL_KEYWORDS.items():
        matches = []
        for kw in keywords:
            kw_lower = kw.lower()
            if kw_lower in lowered_text:
                matches.append(kw)
            elif any(kw_lower in f for f in lowered_files):
                matches.append(kw)
        if matches:
            signals[criterion] = matches

    # Supplement "Test Definition of Virtualized Environments" with direct
    # IaC file presence (Terraform/Bicep/ARM/K8s manifests), independent of
    # any scanning tool being referenced.
    iac_files = [f for f in file_list if f.lower().endswith((".tf", ".bicep")) or "arm-template" in f.lower()]
    if iac_files:
        signals.setdefault("Test Definition of Virtualized Environments", [])
        signals["Test Definition of Virtualized Environments"].extend(iac_files[:10])

    return signals


class AzureDevOpsConnector(BaseSourceControlConnector):
    """
    Expected credentials:
        {
            "organization": "my-org",
            "project": "my-project",
            "token": "<personal-access-token>"
        }
    """

    def __init__(self, credentials: dict) -> None:
        super().__init__(credentials)
        self.organization = credentials.get("organization", "")
        self.project = credentials.get("project", "")
        self.token = credentials.get("token", "")
        self.base_url = f"https://dev.azure.com/{self.organization}/{self.project}/_apis"
        auth_value = base64.b64encode(f":{self.token}".encode()).decode()
        self.headers = {"Authorization": f"Basic {auth_value}"}

    async def health_check(self) -> bool:
        url = f"{self.base_url}/pipelines?api-version={API_VERSION}"
        self._log(f"GET {url}")
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(url, headers=self.headers)
                return response.status_code == 200
        except Exception as exc:
            logger.error("Azure DevOps health_check failed: %s", exc)
            return False

    async def collect(self, repository: str) -> InfrastructureEvidence:
        pipeline_definitions = await self._collect_pipeline_definitions(repository)
        repository_files = await self._collect_repository_files(repository)

        combined_text = "\n".join(p.raw_content for p in pipeline_definitions)
        signals = _detect_signals(combined_text, repository_files)

        return InfrastructureEvidence(
            platform_type="azure_devops",
            repository=repository,
            pipeline_definitions=pipeline_definitions,
            repository_files=repository_files,
            detected_signals=signals,
            raw_metadata={"organization": self.organization, "project": self.project},
            api_call_log=self._api_call_log,
        )

    async def _collect_pipeline_definitions(self, repository: str) -> list[PipelineDefinition]:
        definitions: list[PipelineDefinition] = []
        list_url = f"{self.base_url}/pipelines?api-version={API_VERSION}"
        self._log(f"GET {list_url}")

        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                response = await client.get(list_url, headers=self.headers)
                response.raise_for_status()
                pipelines = response.json().get("value", [])

                for pipeline in pipelines:
                    pipeline_id = pipeline.get("id")
                    name = pipeline.get("name", f"pipeline-{pipeline_id}")

                    detail_url = f"{self.base_url}/pipelines/{pipeline_id}?api-version={API_VERSION}"
                    self._log(f"GET {detail_url}")
                    detail_resp = await client.get(detail_url, headers=self.headers)
                    if detail_resp.status_code != 200:
                        continue
                    detail = detail_resp.json()
                    yaml_path = detail.get("configuration", {}).get("path", "")

                    raw_content = ""
                    if yaml_path:
                        items_url = (
                            f"{self.base_url}/git/repositories/{repository}/items"
                            f"?path={yaml_path}&api-version={API_VERSION}"
                        )
                        self._log(f"GET {items_url}")
                        item_resp = await client.get(items_url, headers=self.headers)
                        if item_resp.status_code == 200:
                            raw_content = item_resp.text

                    definitions.append(PipelineDefinition(name=name, path=yaml_path, raw_content=raw_content))
        except Exception as exc:
            logger.error("Azure DevOps pipeline collection failed: %s", exc, exc_info=True)

        return definitions

    async def _collect_repository_files(self, repository: str) -> list[str]:
        url = (
            f"{self.base_url}/git/repositories/{repository}/items"
            f"?recursionLevel=Full&api-version={API_VERSION}"
        )
        self._log(f"GET {url}")
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(url, headers=self.headers)
                response.raise_for_status()
                items = response.json().get("value", [])
                paths = [item.get("path", "") for item in items if not item.get("isFolder", False)]
                return paths[:MAX_FILES]
        except Exception as exc:
            logger.error("Azure DevOps repository file listing failed: %s", exc, exc_info=True)
            return []
