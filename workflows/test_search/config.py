"""
Test Search Configuration.
Contains system prompts and tool definitions for the agent.
"""
import logging
from langchain_core.tools import tool
from core.logger import get_logger

logger: logging.Logger = get_logger(__name__)

# Main instruction prompt for the LLM
SEARCH_AGENT_SYSTEM_PROMPT: str = """You are a DevSecOps assessment specialist.
Focus on factual analysis. Cite sources.
Output structured findings with severity and recommendations.
"""

@tool
def search_information(query: str) -> str:
    """Searches for DevSecOps-related information based on query."""
    if not query.strip():
        raise ValueError("Query must be non-empty.")
    
    # Simulated search response
    return (
        f"Search results for '{query}':\n"
        "1. Broken Access Control (Critical) - CWE-284\n"
        "2. Injection (Critical) - CWE-79\n"
    )

TOOLS = [search_information]
