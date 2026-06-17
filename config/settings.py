"""
Centralized Application Configuration.
Manages environment variables using pydantic-settings.
"""
import os
from functools import lru_cache
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    """Application settings loaded from environment or .env file."""
    
    # LLM Settings
    OPENAI_API_KEY: str = "your_api_key_here"
    OPENAI_MODEL: str = "gpt-4o-mini"
    OPENAI_TEMPERATURE: float = 0.0
    OPENAI_MAX_TOKENS: Optional[int] = None

    #Database URL
    DATABASE_URL: str

    # Server Settings
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    DEBUG: bool = False
    
    # Logging Settings
    LOG_LEVEL: str = "INFO"

    # App Metadata
    APP_NAME: str = "DevSecOps Assessment Backend"
    APP_VERSION: str = "1.0.0"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Returns a cached singleton instance of Settings."""
    return Settings()
