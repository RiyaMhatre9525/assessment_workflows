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
            
            # Attempt to record FAILED state in database if assessment_id or result_id is known
            assessment_id = None
            result_id = None
            if 'state' in locals() and isinstance(state, dict):
                assessment_id = state.get("assessment_id")
                result_id = state.get("result_id")
            if not assessment_id and isinstance(input_data, dict):
                assessment_id = input_data.get("assessment_id")

            if result_id or assessment_id:
                try:
                    from core.database import SessionLocal
                    from core.repositories.assessment_result_repository import AssessmentResultRepository
                    
                    db = SessionLocal()
                    try:
                        domain_name = getattr(self, "domain_name", "UNKNOWN")
                        if result_id:
                            AssessmentResultRepository.update_assessment_result(
                                db=db,
                                result_id=result_id,
                                status="FAILED",
                                domain_score=0.0,
                                reasoning=f"Workflow terminated due to error: {str(exc)}",
                                improvement_recommendations=[],
                                additional_info={"error": str(exc)}
                            )
                            self.logger.info("Updated status to FAILED in database for result_id=%s", result_id)
                        else:
                            AssessmentResultRepository.insert_assessment_result(
                                db=db,
                                assessment_id=assessment_id,
                                status="FAILED",
                                domain_name=domain_name,
                                domain_score=0.0,
                                reasoning=f"Workflow terminated due to error: {str(exc)}",
                                improvement_recommendations=[],
                                additional_info={"error": str(exc)}
                            )
                            self.logger.info("Saved FAILED status to database for assessment_id=%s", assessment_id)
                    finally:
                        db.close()
                except Exception as db_exc:
                    self.logger.error("Failed to save/update FAILED status to database: %s", db_exc)
            raise


    def get_info(self) -> Dict[str, str]:
        """Returns workflow metadata for API listings."""
        return {"name": self.name, "description": self.description}
