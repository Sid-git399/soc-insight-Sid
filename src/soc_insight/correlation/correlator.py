"""
Event correlation.

Detection rules rarely fire on a single event in isolation -- they need a
window of related activity for one entity (a host, a user, or the pair of
the two). This module builds those windows so rules.py can reason about
sequences instead of individual events.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Optional

from soc_insight.models import NormalizedEvent

DEFAULT_WINDOW_MINUTES = 20


def entity_key(event: NormalizedEvent) -> str:
    """
    The correlation entity is host+user when both are known (this is the
    level most attacks unfold at); falls back to whichever is known.
    """
    host = event.host or "unknown-host"
    user = event.user or "unknown-user"
    return f"host={host}|user={user}"


@dataclass
class EntityWindow:
    entity_key: str
    host: Optional[str]
    user: Optional[str]
    events: list  # list[NormalizedEvent], sorted by timestamp


def build_entity_windows(events: list, window_minutes: int = DEFAULT_WINDOW_MINUTES) -> list[EntityWindow]:
    """
    Groups events per entity, then splits each entity's events into
    contiguous windows: a new window starts whenever the gap since the
    previous event exceeds `window_minutes`. This lets rules correlate
    "burst" activity without conflating unrelated activity days apart.
    """
    by_entity: dict[str, list[NormalizedEvent]] = {}
    for event in sorted(events, key=lambda e: e.timestamp):
        key = entity_key(event)
        by_entity.setdefault(key, []).append(event)

    windows: list[EntityWindow] = []
    gap = timedelta(minutes=window_minutes)
    for key, entity_events in by_entity.items():
        current: list[NormalizedEvent] = []
        last_ts = None
        for event in entity_events:
            if current and (event.timestamp - last_ts) > gap:
                windows.append(_make_window(key, current))
                current = []
            current.append(event)
            last_ts = event.timestamp
        if current:
            windows.append(_make_window(key, current))
    return windows


def _make_window(key: str, events: list) -> EntityWindow:
    host = next((e.host for e in events if e.host), None)
    user = next((e.user for e in events if e.user), None)
    return EntityWindow(entity_key=key, host=host, user=user, events=events)
