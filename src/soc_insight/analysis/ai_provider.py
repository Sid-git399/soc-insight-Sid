"""
AI provider abstraction.

SOC-Insight's analysis layer (incident summaries, evidence explanations,
investigation suggestions, executive/technical summaries) is built against
this interface so the *default* implementation never depends on a paid
external API. A local model can optionally be plugged in later without
changing any calling code.

No API key is ever hard-coded here or anywhere else in the project.
"""
from __future__ import annotations

from abc import ABC, abstractmethod


class AIProvider(ABC):
    """Common interface for anything that can produce incident analysis text."""

    @abstractmethod
    def summarize_incident(self, incident: dict) -> str: ...

    @abstractmethod
    def explain_evidence(self, incident: dict) -> list:
        """Returns a list of {event_id/title, explanation} for the incident's key evidence."""

    @abstractmethod
    def investigation_suggestions(self, incident: dict) -> list:
        """Returns an ordered list of next-step strings."""

    @abstractmethod
    def executive_summary(self, incident: dict) -> str: ...

    @abstractmethod
    def technical_summary(self, incident: dict) -> str: ...
