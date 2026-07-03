"""
workflows/infrastructure_hardening/graph.py

State definition and LangGraph wiring for the infrastructure_hardening
maturity assessment workflow: 5 progressive levels with fail-fast logic.
"""

from typing import Any

from langgraph.graph import StateGraph, END
from typing_extensions import TypedDict

from workflows.base_workflow import BaseWorkflow
from workflows.infrastructure_hardening.connectors import (
    CLOUD_CONNECTOR_REGISTRY,
    VCS_CONNECTOR_REGISTRY,
)
from workflows.infrastructure_hardening.connectors.base import PlatformData
from workflows.infrastructure_hardening.nodes import (
    collect_platform_data_node,
    format_result_node,
    level1_node,
    level2_node,
    level3_node,
    level4_node,
    level5_node,
)


class InfrastructureHardeningState(TypedDict, total=False):
    # Inputs
    assessment_id: str
    vcs_type: str
    vcs_credentials: dict
    cloud_type: str
    cloud_credentials: dict
    repository: str
    # Intermediate
    platform_data: PlatformData
    level_results: dict
    current_level: int
    final_score: float
    stop_assessment: bool
    error_message: str
    result_id: str
    # Output
    final_result: dict
    status: str


def _should_stop(state: dict) -> str:
    return "format_result" if state.get("stop_assessment") else "continue"


class InfrastructureHardeningWorkflow(BaseWorkflow):
    def __init__(self):
        super().__init__(
            name="Infrastructure Hardening Maturity Assessment",
            description=(
                "Assesses infrastructure security hardening maturity across "
                "a connected version control system and a connected cloud "
                "platform, across 5 progressive levels with fail-fast logic."
            ),
        )
        self.domain_name = "infrastructure_hardening"

    def build_graph(self) -> Any:
        graph = StateGraph(InfrastructureHardeningState)

        graph.add_node("collect_platform_data", collect_platform_data_node)
        graph.add_node("level1", level1_node)
        graph.add_node("level2", level2_node)
        graph.add_node("level3", level3_node)
        graph.add_node("level4", level4_node)
        graph.add_node("level5", level5_node)
        graph.add_node("format_result", format_result_node)

        graph.set_entry_point("collect_platform_data")
        graph.add_edge("collect_platform_data", "level1")

        graph.add_conditional_edges(
            "level1", _should_stop,
            {"format_result": "format_result", "continue": "level2"},
        )
        graph.add_conditional_edges(
            "level2", _should_stop,
            {"format_result": "format_result", "continue": "level3"},
        )
        graph.add_conditional_edges(
            "level3", _should_stop,
            {"format_result": "format_result", "continue": "level4"},
        )
        graph.add_conditional_edges(
            "level4", _should_stop,
            {"format_result": "format_result", "continue": "level5"},
        )
        graph.add_edge("level5", "format_result")

        graph.add_edge("format_result", END)
        return graph.compile()

    def initialize_state(self, input_data: dict) -> dict:
        required = ["vcs_type", "vcs_credentials", "cloud_type", "cloud_credentials", "repository"]
        missing = [f for f in required if not input_data.get(f)]
        if missing:
            raise ValueError(f"Missing required input_data fields: {', '.join(missing)}")

        if input_data["vcs_type"] not in VCS_CONNECTOR_REGISTRY:
            raise ValueError(
                f"Unsupported vcs_type '{input_data['vcs_type']}'. "
                f"Supported: {list(VCS_CONNECTOR_REGISTRY.keys())}"
            )
        if input_data["cloud_type"] not in CLOUD_CONNECTOR_REGISTRY:
            raise ValueError(
                f"Unsupported cloud_type '{input_data['cloud_type']}'. "
                f"Supported: {list(CLOUD_CONNECTOR_REGISTRY.keys())}"
            )

        return {
            "assessment_id": input_data.get("assessment_id"),
            "vcs_type": input_data["vcs_type"],
            "vcs_credentials": input_data["vcs_credentials"],
            "cloud_type": input_data["cloud_type"],
            "cloud_credentials": input_data["cloud_credentials"],
            "repository": input_data["repository"],
            "level_results": {},
            "stop_assessment": False,
        }

    def extract_result(self, final_state: dict) -> dict:
        return final_state.get("final_result", {"error": "Assessment did not complete"})
