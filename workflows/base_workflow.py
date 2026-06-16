"""
Abstract Base Workflow.
Defines the standard execution contract for all assessment workflows.
"""
import time
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict
from core.logger import get_logger

class BaseWorkflow(ABC):
    """Abstract base class establishing the workflow lifecycle."""
    
    def __init__(self, name: str, description: str) -> None:
        self.name: str = name
        self.description: str = description
        self.graph: Any = None
        self.logger: logging.Logger = get_logger(f"workflows.{self.__class__.__name__}")
        
        self.logger.info("Initialising workflow: %s", self.name)
        self.graph = self.build_graph()

    @abstractmethod
    def build_graph(self) -> Any:
        """Constructs and returns the LangGraph StateGraph."""
        ...

    @abstractmethod
    def initialize_state(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Prepares the initial state dictionary from request payload."""
        ...

    @abstractmethod
    def extract_result(self, final_state: Dict[str, Any]) -> Dict[str, Any]:
        """Formats the final state into a standard API response."""
        ...

    async def run(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Executes the workflow pipeline end-to-end."""
        start_time: float = time.time()
        try:
            state: Dict[str, Any] = self.initialize_state(input_data)
            if self.graph is None:
                raise RuntimeError("Graph not compiled.")
            
            # Execute the graph asynchronously
            final_state: Dict[str, Any] = await self.graph.ainvoke(state)
            result: Dict[str, Any] = self.extract_result(final_state)
            
            elapsed: float = time.time() - start_time
            self.logger.info("Workflow '%s' completed in %.2fs", self.name, elapsed)
            return result
        except Exception as exc:
            self.logger.error("Workflow '%s' failed", self.name, exc_info=True)
            raise

    def get_info(self) -> Dict[str, str]:
        """Returns workflow metadata for API listings."""
        return {"name": self.name, "description": self.description}
