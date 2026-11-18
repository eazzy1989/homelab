#!/usr/bin/env python3
from __future__ import annotations

from typing import Any


def summarize_guardian(snapshot: dict[str, Any] | None, alerts: list[dict[str, Any]] | None) -> dict[str, Any]:
    snapshot = snapshot or {}
    alerts = alerts or []
    summary = {
        "host": snapshot.get("host"),
        "node": snapshot.get("node"),
        "alert_count": len(alerts),
        "critical_count": sum(1 for a in alerts if str(a.get("severity", "")).lower() == "critical"),
        "warning_count": sum(1 for a in alerts if str(a.get("severity", "")).lower() == "warning"),
        "categories": sorted({str(a.get("category", "unknown")) for a in alerts if a}),
        "top_titles": [str(a.get("title", "")) for a in alerts[:8] if a.get("title")],
        "snapshot_keys": sorted(list(snapshot.keys()))[:40],
    }
    return summary
