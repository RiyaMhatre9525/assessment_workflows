"""
Application Entry Point.
Initializes the FastAPI application and Uvicorn server.
"""
import logging
from datetime import datetime
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from config.settings import get_settings
from core.logger import get_logger
from api.routes import router as api_router
from api.models import HealthResponse

logger: logging.Logger = get_logger(__name__)
settings = get_settings()

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
)

# Enable CORS for frontend interoperability
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)

@app.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Simple probe to verify server readiness."""
    return HealthResponse(
        app_name=settings.APP_NAME,
        version=settings.APP_VERSION,
    )

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower(),
    )
