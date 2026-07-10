"""
Base platform connector and evidence dataclasses for the
Dynamic_Depth_for_Infrastructure workflow.

Every concrete connector must inherit from BaseInfraConnector and implement
health_check() + collect(). Connectors return an InfrastructurePlatformData
instance which is the single source of truth consumed by every level node.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


# --------------------------------------------------------------------------- #
# Evidence dataclasses
# --------------------------------------------------------------------------- #

@dataclass
class ExposedServicesEvidence:
    """Evidence for Level 2 / Control 1 - Test for Exposed Services."""
    exposed_services_scan_found: bool = False
    public_endpoints_identified: bool = False
    kubernetes_exposure_checked: bool = False
    subdomain_enumeration_found: bool = False
    port_scanning_configured: bool = False
    unintended_public_services_check: bool = False
    tools_detected: list = field(default_factory=list)
    # e.g. ["amass", "nmap", "trivy", "kube-bench"]
    scan_in_pipeline: bool = False
    examples: list = field(default_factory=list)


@dataclass
class NetworkSegmentationEvidence:
    """Evidence for Level 2 / Control 2 - Test Network Segmentation."""
    network_segmentation_configured: bool = False
    pod_isolation_configured: bool = False
    namespace_isolation_configured: bool = False
    internal_cluster_restrictions: bool = False
    firewall_rules_found: bool = False
    network_policies_found: bool = False
    nsg_rules_found: bool = False
    tools_detected: list = field(default_factory=list)
    examples: list = field(default_factory=list)


@dataclass
class CloudConfigurationEvidence:
    """Evidence for Level 2 / Control 3 - Test Cloud Configuration."""
    storage_config_checked: bool = False
    iam_config_checked: bool = False
    network_config_checked: bool = False
    security_groups_checked: bool = False
    logging_enabled: bool = False
    monitoring_enabled: bool = False
    encryption_configured: bool = False
    public_exposure_checked: bool = False
    misconfiguration_scan_found: bool = False
    tools_detected: list = field(default_factory=list)
    # e.g. ["defender", "security-center", "prowler", "checkov"]
    examples: list = field(default_factory=list)
    limitation_note: str = ""


@dataclass
class UnauthorizedInstallationEvidence:
    """Evidence for Level 3 / Control 1 - Unauthorized Installation Test."""
    approved_images_policy_found: bool = False
    base_image_verification_found: bool = False
    image_whitelisting_configured: bool = False
    unauthorized_container_detection: bool = False
    cluster_scanning_found: bool = False
    docker_image_validation_found: bool = False
    tools_detected: list = field(default_factory=list)
    examples: list = field(default_factory=list)


@dataclass
class WeakPasswordEvidence:
    """Evidence for Level 3 / Control 2 - Weak Password Test."""
    default_accounts_check: bool = False
    weak_password_scan_found: bool = False
    brute_force_protection_found: bool = False
    standard_username_check: bool = False
    password_policy_found: bool = False
    mfa_configured: bool = False
    tools_detected: list = field(default_factory=list)
    examples: list = field(default_factory=list)
    limitation_note: str = ""


@dataclass
class LoadTestingEvidence:
    """Evidence for Level 4 - Load Testing."""
    load_testing_configured: bool = False
    production_load_test_found: bool = False
    performance_benchmarking_found: bool = False
    stress_testing_found: bool = False
    capacity_validation_found: bool = False
    tools_detected: list = field(default_factory=list)
    # e.g. ["k6", "jmeter", "locust", "gatling", "artillery"]
    examples: list = field(default_factory=list)


@dataclass
class UnusedResourcesEvidence:
    """Evidence for Level 5 - Test for Unused Resources."""
    idle_vm_scan_found: bool = False
    unused_storage_scan_found: bool = False
    unattached_disk_scan_found: bool = False
    unused_public_ip_scan_found: bool = False
    idle_load_balancer_scan_found: bool = False
    unused_kubernetes_resources_scan: bool = False
    orphaned_resources_scan_found: bool = False
    tools_detected: list = field(default_factory=list)
    examples: list = field(default_factory=list)
    limitation_note: str = ""


@dataclass
class InfrastructurePlatformData:
    """
    Aggregate evidence bundle returned by connectors.
    This is the only object level nodes read from.
    """
    source_platform_type: str = ""
    cloud_platform_type: str = ""
    repository: str = ""
    exposed_services: ExposedServicesEvidence = field(default_factory=ExposedServicesEvidence)
    network_segmentation: NetworkSegmentationEvidence = field(default_factory=NetworkSegmentationEvidence)
    cloud_configuration: CloudConfigurationEvidence = field(default_factory=CloudConfigurationEvidence)
    unauthorized_installation: UnauthorizedInstallationEvidence = field(default_factory=UnauthorizedInstallationEvidence)
    weak_password: WeakPasswordEvidence = field(default_factory=WeakPasswordEvidence)
    load_testing: LoadTestingEvidence = field(default_factory=LoadTestingEvidence)
    unused_resources: UnusedResourcesEvidence = field(default_factory=UnusedResourcesEvidence)
    raw_metadata: dict = field(default_factory=dict)
    api_call_log: list = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Base connectors
# --------------------------------------------------------------------------- #

class BaseInfraSCMConnector(ABC):
    """
    Abstract base for SCM connectors in Dynamic_Depth_for_Infrastructure.
    Collects pipeline/config evidence for infrastructure security tooling.
    """

    def __init__(self, credentials: dict) -> None:
        self.credentials = credentials
        self._api_call_log: list[str] = []

    def _log(self, message: str) -> None:
        self._api_call_log.append(message)

    @abstractmethod
    async def health_check(self) -> bool:
        """Return True if credentials are valid and the platform is reachable."""

    @abstractmethod
    async def collect_pipeline_evidence(self, repository: str) -> InfrastructurePlatformData:
        """Collect pipeline-based evidence for all maturity levels."""


class BaseInfraCloudConnector(ABC):
    """
    Abstract base for cloud connectors in Dynamic_Depth_for_Infrastructure.
    Collects cloud resource evidence for infrastructure security controls.
    """

    def __init__(self, credentials: dict) -> None:
        self.credentials = credentials
        self._api_call_log: list[str] = []

    def _log(self, message: str) -> None:
        self._api_call_log.append(message)

    @abstractmethod
    async def health_check(self) -> bool:
        """Return True if credentials are valid and the cloud is reachable."""

    @abstractmethod
    async def enrich_with_cloud_evidence(self, data: InfrastructurePlatformData) -> InfrastructurePlatformData:
        """Enrich the platform data with cloud-specific evidence."""
