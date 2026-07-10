"""
Base classes and shared data structures for Static_Depth_for_Infrastructure
provider connectors.

Two connector families exist:
  - BaseSourceControlConnector → Azure DevOps Git, GitHub, GitLab, Bitbucket,
                                  AWS CodeCommit, ... (pipeline definitions,
                                  IaC files, secret-scanning tool evidence)
  - BaseCloudConnector         → Azure, AWS, GCP, Kubernetes, OpenShift, ...
                                  (deployed cluster/VM/registry/security
                                  posture evidence)

The assessment logic (nodes.py) NEVER talks to a provider API directly — it
only ever reads from the provider-agnostic dataclasses defined here. Adding a
new provider means adding one new connector file + one registry entry in
connectors/__init__.py. No other file changes.

Evidence is represented generically as `detected_signals`: a dict mapping
each canonical criterion name (see config.LEVEL_CRITERIA_NAMES) to the list
of raw indicators (matched keywords, file names, tool/resource names) a
connector found for it.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PipelineDefinition:
    name: str
    path: str
    raw_content: str = ""


@dataclass
class InfrastructureEvidence:
    platform_type: str = ""
    repository: str = ""
    pipeline_definitions: list[PipelineDefinition] = field(default_factory=list)
    repository_files: list[str] = field(default_factory=list)
    # criterion name -> list of matched raw indicators (keywords, file names, tool names)
    detected_signals: dict[str, list[str]] = field(default_factory=dict)
    raw_metadata: dict = field(default_factory=dict)
    api_call_log: list[str] = field(default_factory=list)


@dataclass
class CloudInfrastructureEvidence:
    platform_type: str = ""
    scope: str = ""  # e.g. subscription id, project id
    detected_signals: dict[str, list[str]] = field(default_factory=dict)
    raw_metadata: dict = field(default_factory=dict)
    api_call_log: list[str] = field(default_factory=list)


@dataclass
class InfrastructureDepthPlatformData:
    """Unified, provider-agnostic bundle handed to every assessment node."""
    source_control: InfrastructureEvidence = field(default_factory=InfrastructureEvidence)
    cloud: Optional[CloudInfrastructureEvidence] = None


class BaseSourceControlConnector(ABC):
    """Every source control / DevOps provider (Azure DevOps Git, GitHub,
    GitLab, Bitbucket, AWS CodeCommit, ...) implements this interface.
    Assessment nodes never see provider-specific types — only the
    InfrastructureEvidence dataclass returned by collect()."""

    def __init__(self, credentials: dict) -> None:
        self.credentials = credentials
        self._api_call_log: list[str] = []

    def _log(self, message: str) -> None:
        self._api_call_log.append(message)

    @abstractmethod
    async def collect(self, repository: str) -> InfrastructureEvidence: ...

    @abstractmethod
    async def health_check(self) -> bool: ...


class BaseCloudConnector(ABC):
    """Every cloud provider (Azure, AWS, GCP, Kubernetes, OpenShift, ...)
    implements this interface. Cloud evidence is central to this workflow
    (cluster config, VM config, cloud security posture) but the workflow can
    still run and reach source-control-only criteria without it."""

    def __init__(self, credentials: dict) -> None:
        self.credentials = credentials
        self._api_call_log: list[str] = []

    def _log(self, message: str) -> None:
        self._api_call_log.append(message)

    @abstractmethod
    async def collect(self, scope: str) -> CloudInfrastructureEvidence: ...

    @abstractmethod
    async def health_check(self) -> bool: ...
