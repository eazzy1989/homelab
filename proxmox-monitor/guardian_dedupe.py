#!/usr/bin/env python3
from __future__ import annotations

from typing import Any


def alert_key(alert: dict[str, Any] | None) -> str:
    alert = alert or {}
    category = str(alert.get("category", "unknown"))
    entity = str(alert.get("entity", "unknown"))
    metric = str(alert.get("metric", "status"))
    title = str(alert.get("title", ""))
    return f"{category}:{entity}:{metric}:{title}"


def dedupe_alerts(alerts: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for alert in alerts or []:
        key = alert_key(alert)
        if key in seen:
            continue
        seen.add(key)
        out.append(alert)
    return out
