"""
Singleton LLM Provider.
Ensures a single, reused connection instance to the LLM backend.
"""
import logging
from typing import Optional
from langchain_openai import ChatOpenAI
from config.settings import get_settings
from core.logger import get_logger

logger: logging.Logger = get_logger(__name__)

class LLMProvider:
    """Singleton wrapper for the ChatOpenAI model."""
    _instance: Optional["LLMProvider"] = None
    _llm: Optional[ChatOpenAI] = None

    def __new__(cls) -> "LLMProvider":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._initialise_llm(cls._instance)
        return cls._instance

    def _initialise_llm(self) -> None:
        """Initializes the ChatOpenAI client based on configuration."""
        settings = get_settings()
        if settings.OPENAI_API_KEY in ("your_api_key_here", ""):
            logger.warning("OPENAI_API_KEY is not set.")

        try:
            self._llm = ChatOpenAI(
                model=settings.OPENAI_MODEL,
                temperature=settings.OPENAI_TEMPERATURE,
                max_tokens=settings.OPENAI_MAX_TOKENS,
                openai_api_key=settings.OPENAI_API_KEY,
            )
            logger.info(f"LLM initialised: {settings.OPENAI_MODEL}")
        except Exception as exc:
            logger.critical("Failed to initialise LLM", exc_info=True)
            raise RuntimeError(f"Could not initialise LLM: {exc}") from exc

    def get_llm(self) -> ChatOpenAI:
        """Returns the shared LLM instance."""
        if self._llm is None:
            raise RuntimeError("LLM not initialised.")
        return self._llm

    def get_model_name(self) -> str:
        """Returns the name of the currently configured model."""
        return get_settings().OPENAI_MODEL
