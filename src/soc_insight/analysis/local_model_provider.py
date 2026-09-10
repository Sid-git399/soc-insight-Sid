"""
LocalModelProvider (optional).

If the operator has a local model server (e.g. Ollama, llama.cpp server,
or any OpenAI-compatible local endpoint) they can point SOC-Insight at it
via the SOC_INSIGHT_LOCAL_MODEL_URL environment variable. This is never
enabled by default and the application must remain fully functional
without it -- see RuleBasedProvider, which is used whenever this is not
configured.

No API key is read, stored, or sent from this module. If the configured
endpoint requires authentication that is the operator's responsibility to
configure via their own reverse proxy; this project does not manage
external credentials.
"""
from __future__ import annotations

import json
import os
import urllib.request

from soc_insight.analysis.ai_provider import AIProvider
from soc_insight.analysis.rule_based_provider import RuleBasedProvider

LOCAL_MODEL_URL_ENV = "SOC_INSIGHT_LOCAL_MODEL_URL"
REQUEST_TIMEOUT_SECONDS = 15


class LocalModelProvider(AIProvider):
    """
    Delegates to a local HTTP endpoint for narrative generation, falling
    back to RuleBasedProvider if the endpoint is unavailable or unset, so a
    misconfigured local model never breaks the application.
    """

    def __init__(self, endpoint_url: str | None = None):
        self.endpoint_url = endpoint_url or os.environ.get(LOCAL_MODEL_URL_ENV)
        self._fallback = RuleBasedProvider()

    def _call_local_model(self, prompt: str) -> str | None:
        if not self.endpoint_url:
            return None
        try:
            payload = json.dumps({"prompt": prompt}).encode("utf-8")
            req = urllib.request.Request(
                self.endpoint_url, data=payload, headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("text") or data.get("response")
        except Exception:
            return None  # fail closed to the rule-based fallback, never crash the request

    def summarize_incident(self, incident: dict) -> str:
        base = self._fallback.summarize_incident(incident)
        generated = self._call_local_model(f"Summarize this incident for a SOC analyst:\n{base}")
        return generated or base

    def explain_evidence(self, incident: dict) -> list:
        return self._fallback.explain_evidence(incident)

    def investigation_suggestions(self, incident: dict) -> list:
        return self._fallback.investigation_suggestions(incident)

    def executive_summary(self, incident: dict) -> str:
        base = self._fallback.executive_summary(incident)
        generated = self._call_local_model(f"Rewrite for a non-technical executive audience:\n{base}")
        return generated or base

    def technical_summary(self, incident: dict) -> str:
        return self._fallback.technical_summary(incident)
