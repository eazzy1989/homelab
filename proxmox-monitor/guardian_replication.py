#!/usr/bin/env python3
from __future__ import annotations

from typing import Any

from guardian_alerts import make_alert
from guardian_helpers import safe_str


def build_replication_alerts(snapshot: dict[str, Any] | None) -> list[dict[str, Any]]:
    snapshot = snapshot or {}
    out: list[dict[str, Any]] = []

    rep = safe_str(snapshot.get("replicationstatus") or snapshot.get("replication") or "")
    if not rep:
        return out

    up = rep.upper()
    if any(x in up for x in ("FAIL", "ERROR", "DELAYED", "MISSED", "OFFLINE")):
        out.append(make_alert(
            category="replication",
            severity="warning",
            title="Replication Problem",
            description="Eine Replication ist fehlgeschlagen oder verzögert.",
            cause=rep,
            solution="Replication-Job, Netzwerk und Zielknoten prüfen.",
            diagnosis=["pvesr status", "journalctl -u pvesr -n 100 --no-pager", "pvesh get /cluster/replication"],
            file_path=["/etc/pve/replication.cfg", "/etc/pve"],
            log_file=["/var/log/syslog", "journalctl -u pvesr -n 100 --no-pager"],
            recovery_hint="Replication muss wieder erfolgreich laufen.",
            source="Replication-Check",
            entity=safe_str(snapshot.get("host"), "host"),
            metric="replication",
            threshold="ok",
            current_value=rep,
            summary="Replication Problem",
            extra={"raw": rep},
        ))

    return out
