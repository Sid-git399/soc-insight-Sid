import os

from .ai_provider import AIProvider
from .rule_based_provider import RuleBasedProvider
from .local_model_provider import LocalModelProvider, LOCAL_MODEL_URL_ENV


def get_default_provider() -> AIProvider:
    """
    Returns LocalModelProvider (which itself falls back to rule-based
    output) if SOC_INSIGHT_LOCAL_MODEL_URL is configured, otherwise plain
    RuleBasedProvider. The application never requires this env var.
    """
    if os.environ.get(LOCAL_MODEL_URL_ENV):
        return LocalModelProvider()
    return RuleBasedProvider()


__all__ = ["AIProvider", "RuleBasedProvider", "LocalModelProvider", "get_default_provider"]
