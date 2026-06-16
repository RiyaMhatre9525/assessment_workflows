"""
Core package.
Provides cross-cutting infrastructure like logging and LLM clients.
"""
from core.logger import get_logger  # noqa: F401
from core.llm_provider import LLMProvider  # noqa: F401
