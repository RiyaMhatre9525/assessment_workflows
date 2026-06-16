"""
API Request and Response Models.
Uses Pydantic for validation and OpenAPI schema generation.
"""
from datetime import datetime
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field

class WorkflowRequest(BaseModel):
    """Payload representing an inbound workflow execution request."""
    input_data: Dict[str, Any] = Field(default_factory=dict)

class WorkflowResponse(BaseModel):
    """Standardized response envelope for all workflows."""
    workflow: str
    status: str
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())

class HealthResponse(BaseModel):
    """Health check payload."""
    status: str = "healthy"
    app_name: str
    version: str
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
