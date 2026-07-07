"""
graph.py — LoggingMaturityState + LoggingMaturityWorkflow.

Mirrors the build_domain (PipelineMaturityWorkflow) reference structure,
extended with dual inputs (VCS + Cloud) per the logging_domain spec.
"""

from typing import Any

from langgraph.graph import StateGraph, END
from typing_extensions import TypedDict

from workflows.base_workflow import BaseWorkflow
from workflows.logging_domain.nodes import (
    collect_platform_data_node,
    level1_node,
    level2_node,
    level3_node,
    level4_node,
    level5_node,
    format_result_node,
)


class LoggingMaturityState(TypedDict, total=False):
    # Inputs
    assessment_id: str
    vcs_platform_type: str
    vcs_credentials: dict
    repository: str
    branch: str
    cloud_platform_type: str
    cloud_credentials: dict
    # Intermediate
    vcs_data: Any
    cloud_data: Any
    level_results: dict
    current_level: int
    stop_assessment: bool
    final_score: float
    error_message: str
    result_id: str
    # Output
    final_result: dict
    status: str


def _should_stop(state: dict) -> str:
    return "format_result" if state.get("stop_assessment") else "continue"


class LoggingMaturityWorkflow(BaseWorkflow):
    def __init__(self):
        super().__init__(
            name="Logging Maturity Assessment",
            description=(
                "Assesses logging infrastructure maturity across a connected "
                "Version Control System and a connected Cloud Platform, "
                "using a 5-level progressive fail-fast model."
            ),
        )

    def build_graph(self):
        graph = StateGraph(LoggingMaturityState)

        graph.add_node("collect_platform_data", collect_platform_data_node)
        graph.add_node("level1", level1_node)
        graph.add_node("level2", level2_node)
        graph.add_node("level3", level3_node)
        graph.add_node("level4", level4_node)
        graph.add_node("level5", level5_node)
        graph.add_node("format_result", format_result_node)

        graph.set_entry_point("collect_platform_data")

        # If collect fails (stop_assessment True), go straight to format_result.
        graph.add_conditional_edges(
            "collect_platform_data",
            _should_stop,
            {"format_result": "format_result", "continue": "level1"},
        )

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
        required = [
            "vcs_platform_type",
            "vcs_credentials",
            "repository",
            "cloud_platform_type",
            "cloud_credentials",
        ]
        missing = [f for f in required if not input_data.get(f)]
        if missing:
            raise ValueError(f"Missing required field(s): {', '.join(missing)}")

        return {
            "assessment_id": input_data.get("assessment_id"),
            "vcs_platform_type": input_data["vcs_platform_type"],
            "vcs_credentials": input_data["vcs_credentials"],
            "repository": input_data["repository"],
            "branch": input_data.get("branch", "").strip(),
            "cloud_platform_type": input_data["cloud_platform_type"],
            "cloud_credentials": input_data["cloud_credentials"],
            "level_results": {},
            "stop_assessment": False,
        }

    def extract_result(self, final_state: dict) -> dict:
        return final_state.get("final_result", {"error": "Assessment did not complete"})
