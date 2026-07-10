"""
API Routes.
Exposes endpoints for listing and triggering workflows.
"""
import logging
from datetime import datetime
from typing import Dict
from fastapi import APIRouter, HTTPException, BackgroundTasks
from core.logger import get_logger
from api.models import WorkflowRequest, WorkflowResponse
from workflows.test_search.graph import TestSearchWorkflow
#bulid domain
from workflows.build_domain.graph import PipelineMaturityWorkflow
#deploy domian
from workflows.deployment_domain.graph import DeploymentMaturityWorkflow
from workflows.application_hardening.graph import ApplicationHardeningWorkflow
# patch_management domain
from workflows.patch_management.graph import PatchManagementWorkflow
from workflows.Dynamic_Depth_for_Infrastructure.graph import DynamicDepthForInfrastructureWorkflow
from workflows.Static_Depth_for_Infrastructure.graph import StaticDepthForInfrastructureWorkflow



logger: logging.Logger = get_logger(__name__)

# Registry mapping URL slugs to workflow instances
WORKFLOWS: Dict[str, object] = {
    "test_search": TestSearchWorkflow(),
    "build_domain": PipelineMaturityWorkflow(), 
    "deployment_domain": DeploymentMaturityWorkflow(), 
    "application_hardening": ApplicationHardeningWorkflow(),
    "patch_management": PatchManagementWorkflow(), 
    "Dynamic_Depth_for_Infrastructure": DynamicDepthForInfrastructureWorkflow(),
    "Static_Depth_for_Infrastructure": StaticDepthForInfrastructureWorkflow(),

}

router = APIRouter(prefix="/api", tags=["Workflows"])

@router.post("/execute/{workflow_name}", response_model=WorkflowResponse)
async def execute_workflow(
    workflow_name: str,
    request: WorkflowRequest,
    background_tasks: BackgroundTasks
) -> WorkflowResponse:
    """Triggers the specified workflow asynchronously in the background."""
    workflow = WORKFLOWS.get(workflow_name)
    if not workflow:
        raise HTTPException(status_code=404, detail="Workflow not found")

    try:
        # Pre-validate inputs synchronously to catch bad input early
        workflow.initialize_state(request.input_data)
    except ValueError as ve:
        return WorkflowResponse(
            workflow=workflow_name,
            status="error",
            error=str(ve),
        )
    except Exception as exc:
        logger.error("Validation error", exc_info=True)
        return WorkflowResponse(
            workflow=workflow_name,
            status="error",
            error=str(exc),
        )

    # Queue the workflow run in the background
    background_tasks.add_task(workflow.run, request.input_data)
    
    logger.info("Scheduled workflow execution for '%s' in the background", workflow_name)

    return WorkflowResponse(
        workflow=workflow_name,
        status="in_progress",
        result=None,
    )

@router.get("/workflows")
async def list_workflows() -> dict:
    """Returns a list of all registered workflows."""
    return {
        "workflows": [
            {**wf.get_info(), "key": key} for key, wf in WORKFLOWS.items()
        ]
    }
