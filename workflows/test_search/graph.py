"""
Test Search LangGraph Wiring.
Defines the state schema and graph topology.
"""
import logging
from typing import Any, Dict
from typing_extensions import TypedDict
from langgraph.graph import StateGraph, END
from core.logger import get_logger
from workflows.base_workflow import BaseWorkflow
from workflows.test_search.nodes import SearchNodes

class SearchWorkflowState(TypedDict, total=False):
    """Schema representing the state carried between graph nodes."""
    query: str
    search_results: str
    final_result: Dict[str, Any]
    status: str

class TestSearchWorkflow(BaseWorkflow):
    """Concrete workflow implementation for DevSecOps search."""
    
    def __init__(self) -> None:
        super().__init__(name="Test Search", description="DevSecOps search workflow")

    def build_graph(self) -> Any:
        """Connects the search and process nodes into an executable graph."""
        nodes = SearchNodes()
        graph = StateGraph(SearchWorkflowState)
        
        graph.add_node("search", nodes.search_node)
        graph.add_node("process", nodes.process_node)
        
        graph.add_edge("search", "process")
        graph.add_edge("process", END)
        graph.set_entry_point("search")
        
        return graph.compile()

    def initialize_state(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Prepares the initial state payload."""
        query = input_data.get("query", "")
        if not query.strip():
            raise ValueError("Query is required")
        return {"query": query.strip(), "status": "initialized"}

    def extract_result(self, final_state: Dict[str, Any]) -> Dict[str, Any]:
        """Retrieves the finalized assessment structure."""
        return final_state.get("final_result", {})
