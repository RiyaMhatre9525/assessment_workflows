"""
Test Search Graph Nodes.
Defines functions that transform the workflow state.
"""
import logging
from typing import Any, Dict
from core.logger import get_logger
from workflows.test_search.agents import create_search_agent

class SearchNodes:
    """Container for state-transforming node functions."""
    
    def __init__(self) -> None:
        self.logger: logging.Logger = get_logger(f"{__name__}.{self.__class__.__name__}")
        self.agent = create_search_agent()

    async def search_node(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Invokes the search agent and records raw results."""
        query: str = state.get("query", "")
        if not query.strip():
            return {"search_results": "No query", "status": "skipped"}

        try:
            result = await self.agent.ainvoke({"messages": [("user", query)]})
            messages = result.get("messages", [])
            return {
                "search_results": messages[-1].content if messages else "",
                "status": "search_completed"
            }
        except Exception as exc:
            self.logger.error("search_node failed", exc_info=True)
            return {"search_results": str(exc), "status": "search_failed"}

    async def process_node(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Formats raw search results into a structured assessment."""
        query: str = state.get("query", "")
        search_results: str = state.get("search_results", "")
        status: str = state.get("status", "unknown")

        try:
            succeeded = status == "search_completed"
            return {
                "final_result": {
                    "query": query,
                    "assessment": search_results,
                    "search_successful": succeeded,
                    "metadata": {
                        "workflow": "test_search", 
                        "status": "completed" if succeeded else "failed"
                    },
                },
                "status": "completed" if succeeded else "failed",
            }
        except Exception as exc:
            self.logger.error("process_node failed", exc_info=True)
            return {"status": "processing_failed"}
