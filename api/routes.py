"""
API Routes.
Exposes endpoints for listing and triggering workflows.
"""
import logging
from datetime import datetime
from typing import Dict
from fastapi import APIRouter, HTTPException
from core.logger import get_logger
from api.models import WorkflowRequest, WorkflowResponse
from workflows.test_search.graph import TestSearchWorkflow
#bulid domain
from workflows.build_domain.graph import PipelineMaturityWorkflow

logger: logging.Logger = get_logger(__name__)

# Registry mapping URL slugs to workflow instances
WORKFLOWS: Dict[str, object] = {
    "test_search": TestSearchWorkflow(),
    "build_domain": PipelineMaturityWorkflow(), 
}

router = APIRouter(prefix="/api", tags=["Workflows"])

@router.post("/execute/{workflow_name}", response_model=WorkflowResponse)
async def execute_workflow(workflow_name: str, request: WorkflowRequest) -> WorkflowResponse:
    """Triggers the specified workflow using the provided data payload."""
    workflow = WORKFLOWS.get(workflow_name)
    if not workflow:
        raise HTTPException(status_code=404, detail="Workflow not found")

    try:
        result = await workflow.run(request.input_data)
        return WorkflowResponse(
            workflow=workflow_name,
            status="success",
            result=result,
        )
    except ValueError as ve:
        return WorkflowResponse(
            workflow=workflow_name,
            status="error",
            error=str(ve),
        )
    except Exception as exc:
        logger.error("Workflow error", exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))

@router.get("/workflows")
async def list_workflows() -> dict:
    """Returns a list of all registered workflows."""
    return {
        "workflows": [
            {**wf.get_info(), "key": key} for key, wf in WORKFLOWS.items()
        ]
    }
