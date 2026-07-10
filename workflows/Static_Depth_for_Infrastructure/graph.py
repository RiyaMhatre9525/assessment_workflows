"""
Graph wiring for the Static_Depth_for_Infrastructure workflow.
"""

from __future__ import annotations

from typing import Any, TypedDict

from langgraph.graph import END, StateGraph

from workflows.base_workflow import BaseWorkflow
from workflows.Static_Depth_for_Infrastructure.nodes import (
    _should_stop,
    collect_platform_data_node,
    format_result_node,
    level1_node,
    level2_node,
    level3_node,
    level4_node,
    level5_node,
)


class InfrastructureDepthState(TypedDict, total=False):
    # Inputs
    source_control_platform: str
    cloud_platform: str
    credentials: dict
    repository: str
    assessment_id: str
    # Intermediate
    platform_data: Any
    level_results: dict
    current_level: int
    stop_assessment: bool
    error_message: str
    result_id: str
    # Output
    final_result: dict
    status: str


class StaticDepthForInfrastructureWorkflow(BaseWorkflow):
    def __init__(self):
        super().__init__(
            name="Static Depth for Infrastructure Assessment",
            description=(
                "Assesses the Static Security Maturity of Infrastructure "
                "across 5 progressive levels, analyzing source code "
                "repositories and cloud infrastructure configuration via "
                "provider adapters."
            ),
        )

    def build_graph(self):
        graph = StateGraph(InfrastructureDepthState)

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
        platform = input_data.get("platform", {})
        source_control_platform = platform.get("source_control")
        cloud_platform = platform.get("cloud_provider") or platform.get("cloud")
        credentials = input_data.get("credentials", {})

        if not source_control_platform:
            raise ValueError("Missing required field: platform.source_control")
        if not credentials:
            raise ValueError("Missing required field: credentials")

        repository = (
            input_data.get("repository")
            or credentials.get("repository")
            or credentials.get("project", "")
        )

        return {
            "source_control_platform": source_control_platform,
            "cloud_platform": cloud_platform,
            "credentials": credentials,
            "repository": repository,
            "assessment_id": input_data.get("assessment_id"),
            "level_results": {},
            "stop_assessment": False,
            "status": "initialized",
        }

    def extract_result(self, final_state: dict) -> dict:
        return final_state.get("final_result", {"error": "Assessment did not complete"})
