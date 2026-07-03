"""
graph.py — state definition and workflow wiring for patch_management.
"""

from typing import Any, TypedDict

from langgraph.graph import END, StateGraph

from core.logger import get_logger
from workflows.base_workflow import BaseWorkflow
from workflows.patch_management.connectors import CONNECTOR_REGISTRY
from workflows.patch_management.nodes import (
    collect_platform_data_node,
    format_result_node,
    level1_node,
    level2_node,
    level3_node,
    level4_node,
    level5_node,
)

logger = get_logger(__name__)


class PatchManagementState(TypedDict, total=False):
    # Inputs
    assessment_id: str
    platform_type: str
    credentials: dict
    repository: str
    # Intermediate
    platform_data: Any
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


class PatchManagementWorkflow(BaseWorkflow):
    def __init__(self):
        super().__init__(
            name="Patch Management Assessment",
            description=(
                "Assesses Patch Management maturity across SCM and cloud platforms "
                "using a fail-fast, 5-level progressive model."
            ),
        )
        self.logger = logger
        self.domain_name = "patch_management"

    def build_graph(self):
        graph = StateGraph(PatchManagementState)

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
        platform_type = input_data.get("platform")
        credentials = input_data.get("credentials")

        if not platform_type:
            raise ValueError("Missing required field: 'platform'.")
        if platform_type not in CONNECTOR_REGISTRY:
            raise ValueError(
                f"Unsupported platform '{platform_type}'. "
                f"Supported platforms: {list(CONNECTOR_REGISTRY.keys())}."
            )
        if not credentials or not isinstance(credentials, dict):
            raise ValueError("Missing required field: 'credentials'.")

        repository = credentials.get("repository", "")
        if not repository:
            raise ValueError("credentials.repository is required.")

        return {
            "assessment_id": input_data.get("assessment_id"),
            "platform_type": platform_type,
            "credentials": credentials,
            "repository": repository,
            "level_results": {},
            "stop_assessment": False,
        }

    def extract_result(self, final_state: dict) -> dict:
        return final_state.get("final_result", {"error": "Assessment did not complete"})
