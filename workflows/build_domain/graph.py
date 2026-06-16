"""
LangGraph wiring for the Pipeline Maturity Assessment workflow.

Graph structure:
    collect_platform_data
         ↓
       level1  ──(fail)──▶ format_result
         ↓ (pass)
       level2  ──(fail)──▶ format_result
         ↓ (pass)
       level3  ──(fail)──▶ format_result
         ↓ (pass)
       level4  ──(fail)──▶ format_result
         ↓ (pass)
       level5
         ↓
      format_result
         ↓
        END

The stop_assessment flag in state drives the conditional edges; each
assessment node sets it to True on failure, and format_result_node is
always the terminal step.
"""

from __future__ import annotations

from typing import Any
from typing_extensions import TypedDict

from langgraph.graph import END, StateGraph

from workflows.base_workflow import BaseWorkflow
from workflows.build_domain.nodes import (
    collect_platform_data_node,
    format_result_node,
    level1_node,
    level2_node,
    level3_node,
    level4_node,
    level5_node,
)
from core.logger import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# State schema
# ---------------------------------------------------------------------------

class PipelineMaturityState(TypedDict, total=False):
    # --- Inputs (set by initialize_state) ---
    platform_type: str        # "github" | "azure_devops" | …
    credentials: dict         # platform-specific auth
    repository: str           # "owner/repo" or "project/repo"

    # --- Intermediate ---
    platform_data: Any        # PlatformData object from connector
    level_results: dict       # {level_int: result_dict}
    current_level: int        # highest level attempted
    stop_assessment: bool     # fail-fast flag
    final_score: float        # score at the stopping level
    error_message: str        # set on connector/LLM error

    # --- Output ---
    final_result: dict
    status: str


# ---------------------------------------------------------------------------
# Conditional edge router
# ---------------------------------------------------------------------------

def _should_stop(state: PipelineMaturityState) -> str:
    """
    Return the next node name based on the stop_assessment flag.

    Used as the conditional edge after each assessment level node.
    """
    if state.get("stop_assessment", False):
        return "format_result"
    return "continue"


# ---------------------------------------------------------------------------
# Workflow class
# ---------------------------------------------------------------------------

class PipelineMaturityWorkflow(BaseWorkflow):
    """
    Multi-level DevSecOps pipeline maturity assessment workflow.

    Accepts a platform type + credentials and progressively assesses
    the target repository against 5 maturity levels, stopping immediately
    when a level fails (fail-fast pattern).
    """

    def __init__(self) -> None:
        super().__init__(
            name="Pipeline Maturity Assessment",
            description=(
                "Evaluates build pipeline maturity across version control and cloud "
                "platforms using a progressive, fail-fast 5-level model."
            ),
        )

    # ------------------------------------------------------------------
    # BaseWorkflow abstract methods
    # ------------------------------------------------------------------

    def build_graph(self) -> Any:
        """Wire the LangGraph StateGraph and return the compiled graph."""
        graph = StateGraph(PipelineMaturityState)

        # Register nodes
        graph.add_node("collect_platform_data", collect_platform_data_node)
        # graph.add_node("level1", level1_node)
        graph.add_node("level2", level2_node)
        graph.add_node("level3", level3_node)
        graph.add_node("level4", level4_node)
        graph.add_node("level5", level5_node)
        graph.add_node("format_result", format_result_node)

        # Entry point
        graph.set_entry_point("collect_platform_data")

        # collect → level1 (always, but level1 checks stop_assessment internally)
        graph.add_edge("collect_platform_data", "level1")

        # Each level: stop if failed, else advance
        for current, next_level in [
            # ("level1", "level2"),
            ("level2", "level3"),
            ("level3", "level4"),
            ("level4", "level5"),
        ]:
            graph.add_conditional_edges(
                current,
                _should_stop,
                {
                    "format_result": "format_result",
                    "continue": next_level,
                },
            )

        # Level 5 always goes to format_result (it sets stop_assessment=True)
        graph.add_edge("level5", "format_result")

        # format_result → END
        graph.add_edge("format_result", END)

        return graph.compile()

    def initialize_state(self, input_data: dict) -> dict:
        """
        Validate and transform API input_data into the initial graph state.

        Args:
            input_data: dict with keys:
                platform_type  (required) – "github" | "azure_devops"
                credentials    (required) – auth dict for the platform
                repository     (required) – "owner/repo"

        Raises:
            ValueError: if required fields are missing.
        """
        platform_type = input_data.get("platform_type", "").strip()
        credentials = input_data.get("credentials")
        repository = input_data.get("repository", "").strip()

        if not platform_type:
            raise ValueError("'platform_type' is required (e.g. 'github', 'azure_devops')")
        if not credentials or not isinstance(credentials, dict):
            raise ValueError("'credentials' must be a non-empty dict")
        if not repository:
            raise ValueError("'repository' is required (e.g. 'owner/repo')")

        logger.info(
            "initialize_state: platform=%s repository=%s", platform_type, repository
        )

        return {
            "platform_type": platform_type,
            "credentials": credentials,
            "repository": repository,
            "level_results": {},
            "current_level": 0,
            "stop_assessment": False,
            "final_score": 0.0,
            "status": "initialized",
        }

    def extract_result(self, final_state: dict) -> dict:
        """
        Pull the formatted assessment result from the final graph state.

        Returns a fallback error dict if format_result_node did not run.
        """
        result = final_state.get("final_result")
        if result:
            return result

        # Fallback: surface whatever error we have
        return {
            "maturity_level": 0,
            "score": 0.0,
            "score_range": "N/A",
            "assessment_details": {
                "passed_criteria": [],
                "failed_criteria": ["Assessment did not complete"],
                "reasoning": final_state.get("error_message", "Unknown error"),
            },
            "improvement_recommendations": [],
        }
