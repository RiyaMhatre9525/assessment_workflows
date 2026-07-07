"""
graph.py — State definition and StateGraph wiring for the Monitoring
Maturity Assessment workflow. Mirrors workflows/build_domain/graph.py.
"""

from typing import Any, TypedDict

from langgraph.graph import StateGraph, END

from workflows.base_workflow import BaseWorkflow
from .nodes import (
    collect_platform_data_node,
    level1_node,
    level2_node,
    level3_node,
    level4_node,
    level5_node,
    format_result_node,
    _should_stop,
)


class MonitoringMaturityState(TypedDict, total=False):
    # Inputs
    assessment_id: str
    vcs_platform_type: str
    cloud_platform_type: str
    repository: str
    vcs_credentials: dict
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


class MonitoringMaturityWorkflow(BaseWorkflow):
    def __init__(self):
        super().__init__(
            name="Monitoring Maturity Assessment",
            description=(
                "Assesses monitoring and observability maturity across a connected "
                "VCS platform (monitoring-as-code configuration) and a connected "
                "cloud platform (live alerting/cost/dashboard configuration) across "
                "5 progressive maturity levels with fail-fast logic."
            ),
        )

    def build_graph(self):
        graph = StateGraph(MonitoringMaturityState)

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
            "level1", _should_stop, {"format_result": "format_result", "continue": "level2"}
        )
        graph.add_conditional_edges(
            "level2", _should_stop, {"format_result": "format_result", "continue": "level3"}
        )
        graph.add_conditional_edges(
            "level3", _should_stop, {"format_result": "format_result", "continue": "level4"}
        )
        graph.add_conditional_edges(
            "level4", _should_stop, {"format_result": "format_result", "continue": "level5"}
        )
        graph.add_edge("level5", "format_result")

        graph.add_edge("format_result", END)
        return graph.compile()

    def initialize_state(self, input_data: dict) -> dict:
        required = [
            "assessment_id",
            "vcs_platform_type",
            "cloud_platform_type",
            "repository",
            "vcs_credentials",
            "cloud_credentials",
        ]
        missing = [field for field in required if not input_data.get(field)]
        if missing:
            raise ValueError(f"Missing required field(s): {', '.join(missing)}")

        return {
            "assessment_id": input_data["assessment_id"],
            "vcs_platform_type": input_data["vcs_platform_type"],
            "cloud_platform_type": input_data["cloud_platform_type"],
            "repository": input_data["repository"],
            "vcs_credentials": input_data["vcs_credentials"],
            "cloud_credentials": input_data["cloud_credentials"],
            "level_results": {},
            "stop_assessment": False,
        }

    def extract_result(self, final_state: dict) -> dict:
        return final_state.get("final_result", {"error": "Assessment did not complete"})
