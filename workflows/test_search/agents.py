"""
Test Search Agent Factory.
Wires tools, LLM, and prompts into a LangGraph ReAct agent.
"""
import logging
from typing import Any
from langgraph.prebuilt import create_react_agent
from core.llm_provider import LLMProvider
from core.logger import get_logger
from workflows.test_search.config import SEARCH_AGENT_SYSTEM_PROMPT, TOOLS

logger: logging.Logger = get_logger(__name__)

def create_search_agent() -> Any:
    """Creates a ReAct agent equipped with search tools."""
    llm = LLMProvider().get_llm()
    agent = create_react_agent(
        model=llm,
        tools=TOOLS,
        prompt=SEARCH_AGENT_SYSTEM_PROMPT
    )
    return agent
