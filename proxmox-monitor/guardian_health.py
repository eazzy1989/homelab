#!/usr/bin/env python3
from __future__ import annotations

from typing import Any


def build_health_snapshot(snapshot: dict[str, Any] | None, alerts: list[dict[str, Any]] | None, summary: dict[str, Any] | None) -> dict[str, Any]:
    snapshot = snapshot or {}
    alerts = alerts or []
    summary = summary or {}

    critical = [
        a for a in alerts
        if str(a.get("severity", "")).lower() == "critical"
    ]

    warning = [
        a for a in alerts
        if str(a.get("severity", "")).lower() == "warning"
    ]

    score = 100
    score -= len(critical) * 30
    score -= len(warning) * 10

    score = max(0, score)

    if score >= 90:
        health = "ok"
    elif score >= 70:
        health = "warning"
    else:
        health = "critical"

    return {
        "health": health,
        "health_score": score,
        "alerts": alerts[:50],
        "summary": summary,
        "host": snapshot.get("host"),
        "node": snapshot.get("node"),
        "counts": {
            "alerts": len(alerts),
            "critical": len(critical),
            "warning": len(warning),
        },
    }
