from typing import Any
from typing_extensions import TypedDict
from langgraph.graph import StateGraph, END
from workflows.base_workflow import BaseWorkflow
from workflows.deployment_domain.nodes import (
    collect_platform_data_node,
    level1_node,
    level2_node,
    level3_node,
    level4_node,
    level5_node,
    format_result_node,
)


class DeploymentDomainState(TypedDict, total=False):
    assessment_id: str
    platform_type: str
    repository: str
    credentials: dict
    platform_data: Any
    level_results: dict
    current_level: int
    stop_assessment: bool
    final_score: float
    last_level_detail: dict
    error_message: str
    final_result: dict
    status: str


def _should_stop(state: dict) -> str:
    return "format_result" if state.get("stop_assessment") else "continue"


class DeploymentMaturityWorkflow(BaseWorkflow):

    domain_name = "deployment_domain"

    def __init__(self) -> None:
        super().__init__(
            name="Deployment Maturity Assessment",
            description="Progressive 5-level deployment maturity assessment across VCS and cloud platforms.",
        )

    def build_graph(self):
        graph = StateGraph(DeploymentDomainState)

        graph.add_node("collect_platform_data", collect_platform_data_node)
        graph.add_node("level1", level1_node)
        graph.add_node("level2", level2_node)
        graph.add_node("level3", level3_node)
        graph.add_node("level4", level4_node)
        graph.add_node("level5", level5_node)
        graph.add_node("format_result", format_result_node)

        graph.set_entry_point("collect_platform_data")
        graph.add_conditional_edges(
            "collect_platform_data",
            _should_stop,
            {"format_result": "format_result", "continue": "level1"},
        )
        graph.add_conditional_edges(
            "level1",
            _should_stop,
            {"format_result": "format_result", "continue": "level2"},
        )
        graph.add_conditional_edges(
            "level2",
            _should_stop,
            {"format_result": "format_result", "continue": "level3"},
        )
        graph.add_conditional_edges(
            "level3",
            _should_stop,
            {"format_result": "format_result", "continue": "level4"},
        )
        graph.add_conditional_edges(
            "level4",
            _should_stop,
            {"format_result": "format_result", "continue": "level5"},
        )
        graph.add_edge("level5", "format_result")
        graph.add_edge("format_result", END)

        return graph.compile()

    def initialize_state(self, input_data: dict) -> dict:
        platform_type = input_data.get("platform_type", "").strip()
        if not platform_type:
            raise ValueError("'platform_type' is required.")

        credentials = input_data.get("credentials")
        if not credentials or not isinstance(credentials, dict):
            raise ValueError("'credentials' must be a non-empty dict.")

        repository = input_data.get("repository", "").strip()
        if not repository:
            raise ValueError("'repository' is required (e.g. 'myorg/myrepo').")

        return {
            "assessment_id": input_data.get("assessment_id", ""),
            "platform_type": platform_type,
            "repository": repository,
            "credentials": credentials,
            "level_results": {},
            "stop_assessment": False,
        }

    def extract_result(self, final_state: dict) -> dict:
        return final_state.get("final_result", {"error": "Assessment did not complete."})
