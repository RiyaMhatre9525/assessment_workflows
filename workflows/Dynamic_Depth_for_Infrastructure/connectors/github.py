"""
GitHub connector for the Dynamic_Depth_for_Infrastructure workflow.

Scans GitHub Actions workflow YAML files for evidence of infrastructure
security tooling configured in CI/CD pipelines.

Expected credentials shape:
{
    "token": "<github-pat>",
    "repository": "org/repo"
}
"""

import base64
import re

import httpx

from core.logger import get_logger
from workflows.Dynamic_Depth_for_Infrastructure.connectors.base import (
    BaseInfraSCMConnector,
    CloudConfigurationEvidence,
    ExposedServicesEvidence,
    InfrastructurePlatformData,
    LoadTestingEvidence,
    NetworkSegmentationEvidence,
    UnauthorizedInstallationEvidence,
    UnusedResourcesEvidence,
    WeakPasswordEvidence,
)

logger = get_logger(__name__)

GITHUB_API_BASE = "https://api.github.com"

# Keyword maps for pipeline scanning
EXPOSED_SERVICES_KEYWORDS = [
    "amass", "nmap", "masscan", "shodan", "subfinder",
    "port-scan", "port_scan", "expose", "public-endpoint",
    "kube-bench", "kubesec", "trivy", "exposed",
]

NETWORK_SEGMENTATION_KEYWORDS = [
    "network-policy", "networkpolicy", "pod-isolation",
    "namespace-isolation", "firewall", "nsg", "security-group",
    "calico", "cilium", "network-segment", "vpc",
]

CLOUD_CONFIG_KEYWORDS = [
    "checkov", "tfsec", "prowler", "defender", "security-center",
    "azure-policy", "iam-scan", "storage-scan", "encryption",
    "misconfig", "cloud-config", "compliance-scan",
]

CONTAINER_SECURITY_KEYWORDS = [
    "trivy", "snyk", "anchore", "clair", "docker-bench",
    "image-scan", "container-scan", "admission-webhook",
    "opa", "kyverno", "image-policy", "whitelist",
]

WEAK_PASSWORD_KEYWORDS = [
    "password-policy", "mfa", "multi-factor", "brute-force",
    "account-lockout", "hydra", "medusa", "default-credentials",
    "password-scan", "credential-scan",
]

LOAD_TEST_KEYWORDS = [
    "k6", "jmeter", "locust", "gatling", "artillery",
    "load-test", "load_test", "stress-test", "performance-test",
    "benchmark", "capacity-test",
]

UNUSED_RESOURCE_KEYWORDS = [
    "idle-vm", "unused-disk", "orphaned", "cleanup",
    "resource-cleanup", "unused-ip", "idle-resource",
    "azure-advisor", "cost-management", "resource-optimizer",
]


class GitHubConnector(BaseInfraSCMConnector):
    def __init__(self, credentials: dict) -> None:
        super().__init__(credentials)
        self.token = credentials.get("token", "")
        self._headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
        }

    async def health_check(self) -> bool:
        url = f"{GITHUB_API_BASE}/user"
        self._log(f"GET {url}")
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(url, headers=self._headers)
                return resp.status_code == 200
        except Exception as exc:
            logger.error("GitHub health_check failed: %s", exc, exc_info=True)
            return False

    async def collect_pipeline_evidence(self, repository: str) -> InfrastructurePlatformData:
        data = InfrastructurePlatformData(
            source_platform_type="github",
            repository=repository,
        )

        combined_text = await self._get_all_pipeline_content(repository)

        data.exposed_services = self._detect_exposed_services(combined_text)
        data.network_segmentation = self._detect_network_segmentation(combined_text)
        data.cloud_configuration = self._detect_cloud_configuration(combined_text)
        data.unauthorized_installation = self._detect_unauthorized_installation(combined_text)
        data.weak_password = self._detect_weak_password(combined_text)
        data.load_testing = self._detect_load_testing(combined_text)
        data.unused_resources = self._detect_unused_resources(combined_text)

        data.api_call_log = list(self._api_call_log)
        return data

    # ------------------------------------------------------------------ #
    # Pipeline content collector
    # ------------------------------------------------------------------ #

    async def _get_all_pipeline_content(self, repository: str) -> str:
        combined = []
        url = f"{GITHUB_API_BASE}/repos/{repository}/actions/workflows"
        self._log(f"GET {url}")
        try:
            async with httpx.AsyncClient(timeout=20, headers=self._headers) as client:
                resp = await client.get(url)
                if resp.status_code != 200:
                    return ""
                workflows = resp.json().get("workflows", [])
                for workflow in workflows:
                    path = workflow.get("path", "")
                    content_url = f"{GITHUB_API_BASE}/repos/{repository}/contents/{path}"
                    self._log(f"GET {content_url}")
                    content_resp = await client.get(content_url)
                    if content_resp.status_code == 200:
                        encoded = content_resp.json().get("content", "")
                        try:
                            text = base64.b64decode(encoded).decode("utf-8", errors="ignore")
                            combined.append(text)
                        except Exception:
                            pass

                # Also check IaC files
                for iac_path in ["main.tf", "infrastructure.tf", "kubernetes/", "k8s/", "helm/"]:
                    iac_url = f"{GITHUB_API_BASE}/repos/{repository}/contents/{iac_path}"
                    self._log(f"GET {iac_url}")
                    iac_resp = await client.get(iac_url)
                    if iac_resp.status_code == 200:
                        combined.append(str(iac_resp.json()))
        except Exception as exc:
            logger.warning("Failed to collect GitHub pipeline content: %s", exc)

        return "\n".join(combined).lower()

    # ------------------------------------------------------------------ #
    # Evidence detectors
    # ------------------------------------------------------------------ #

    def _detect_exposed_services(self, text: str) -> ExposedServicesEvidence:
        evidence = ExposedServicesEvidence()
        tools = [kw for kw in EXPOSED_SERVICES_KEYWORDS if kw in text]
        if tools:
            evidence.tools_detected = tools
            evidence.exposed_services_scan_found = True
            evidence.scan_in_pipeline = True
            evidence.port_scanning_configured = any(k in tools for k in ["nmap", "masscan", "port-scan"])
            evidence.subdomain_enumeration_found = "amass" in tools or "subfinder" in tools
            evidence.kubernetes_exposure_checked = "kube-bench" in tools or "kubesec" in tools
            evidence.public_endpoints_identified = "expose" in tools or "public-endpoint" in tools
            evidence.examples = tools[:5]
        return evidence

    def _detect_network_segmentation(self, text: str) -> NetworkSegmentationEvidence:
        evidence = NetworkSegmentationEvidence()
        tools = [kw for kw in NETWORK_SEGMENTATION_KEYWORDS if kw in text]
        if tools:
            evidence.tools_detected = tools
            evidence.network_segmentation_configured = True
            evidence.pod_isolation_configured = any(k in tools for k in ["pod-isolation", "calico", "cilium"])
            evidence.namespace_isolation_configured = "namespace-isolation" in tools
            evidence.firewall_rules_found = any(k in tools for k in ["firewall", "nsg", "security-group"])
            evidence.network_policies_found = any(k in tools for k in ["network-policy", "networkpolicy"])
            evidence.examples = tools[:5]
        return evidence

    def _detect_cloud_configuration(self, text: str) -> CloudConfigurationEvidence:
        evidence = CloudConfigurationEvidence()
        tools = [kw for kw in CLOUD_CONFIG_KEYWORDS if kw in text]
        if tools:
            evidence.tools_detected = tools
            evidence.misconfiguration_scan_found = True
            evidence.storage_config_checked = "storage-scan" in tools
            evidence.iam_config_checked = "iam-scan" in tools
            evidence.encryption_configured = "encryption" in tools
            evidence.logging_enabled = "azure-policy" in tools or "compliance-scan" in tools
            evidence.monitoring_enabled = "defender" in tools or "security-center" in tools
            evidence.examples = tools[:5]
        else:
            evidence.limitation_note = (
                "No cloud configuration scanning tools detected in pipeline. "
                "Provide Azure credentials for direct cloud resource checks."
            )
        return evidence

    def _detect_unauthorized_installation(self, text: str) -> UnauthorizedInstallationEvidence:
        evidence = UnauthorizedInstallationEvidence()
        tools = [kw for kw in CONTAINER_SECURITY_KEYWORDS if kw in text]
        if tools:
            evidence.tools_detected = tools
            evidence.cluster_scanning_found = True
            evidence.docker_image_validation_found = any(k in tools for k in ["trivy", "snyk", "anchore", "clair"])
            evidence.image_whitelisting_configured = any(k in tools for k in ["opa", "kyverno", "image-policy", "whitelist"])
            evidence.approved_images_policy_found = "admission-webhook" in tools or "kyverno" in tools
            evidence.base_image_verification_found = "trivy" in tools or "anchore" in tools
            evidence.examples = tools[:5]
        return evidence

    def _detect_weak_password(self, text: str) -> WeakPasswordEvidence:
        evidence = WeakPasswordEvidence()
        tools = [kw for kw in WEAK_PASSWORD_KEYWORDS if kw in text]
        if tools:
            evidence.tools_detected = tools
            evidence.weak_password_scan_found = True
            evidence.mfa_configured = "mfa" in tools or "multi-factor" in tools
            evidence.brute_force_protection_found = "brute-force" in tools or "account-lockout" in tools
            evidence.password_policy_found = "password-policy" in tools
            evidence.default_accounts_check = "default-credentials" in tools
            evidence.examples = tools[:5]
        else:
            evidence.limitation_note = (
                "No password/credential scanning tools detected in pipeline. "
                "Azure AD credential policies require cloud connector access."
            )
        return evidence

    def _detect_load_testing(self, text: str) -> LoadTestingEvidence:
        evidence = LoadTestingEvidence()
        tools = [kw for kw in LOAD_TEST_KEYWORDS if kw in text]
        if tools:
            evidence.tools_detected = tools
            evidence.load_testing_configured = True
            evidence.stress_testing_found = "stress-test" in tools
            evidence.performance_benchmarking_found = "benchmark" in tools or "performance-test" in tools
            evidence.capacity_validation_found = "capacity-test" in tools
            evidence.production_load_test_found = "load-test" in tools or "load_test" in tools
            evidence.examples = tools[:5]
        return evidence

    def _detect_unused_resources(self, text: str) -> UnusedResourcesEvidence:
        evidence = UnusedResourcesEvidence()
        tools = [kw for kw in UNUSED_RESOURCE_KEYWORDS if kw in text]
        if tools:
            evidence.tools_detected = tools
            evidence.idle_vm_scan_found = "idle-vm" in tools or "idle-resource" in tools
            evidence.unused_storage_scan_found = "unused-disk" in tools or "resource-cleanup" in tools
            evidence.orphaned_resources_scan_found = "orphaned" in tools or "cleanup" in tools
            evidence.unused_public_ip_scan_found = "unused-ip" in tools
            evidence.examples = tools[:5]
        else:
            evidence.limitation_note = (
                "No unused resource scanning detected in pipeline. "
                "Azure Advisor access required for full unused resource analysis."
            )
        return evidence
