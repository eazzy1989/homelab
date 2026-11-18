#!/usr/bin/env python3
from __future__ import annotations

from typing import Any

from guardian_alerts import make_alert
from guardian_helpers import safe_str


def build_corosync_alerts(snapshot: dict[str, Any] | None) -> list[dict[str, Any]]:
    snapshot = snapshot or {}
    out: list[dict[str, Any]] = []

    corosync = safe_str(snapshot.get("corosyncstatus") or snapshot.get("quorum") or "")
    if not corosync:
        return out

    up = corosync.upper()
    if any(x in up for x in ("NO QUORUM", "OFFLINE", "FAULT", "LINK DOWN", "LOSS")):
        out.append(make_alert(
            category="cluster",
            severity="critical",
            title="Corosync / Quorum Problem",
            description="Corosync oder Quorum ist gestört.",
            cause=corosync,
            solution="Cluster-Mitglieder, Netz, Links und Quorum prüfen.",
            diagnosis=["pvecm status", "corosync-cfgtool -s", "journalctl -u corosync -n 100 --no-pager", "ip addr"],
            file_path=["/etc/pve/corosync.conf", "/etc/corosync"],
            log_file=["/var/log/syslog", "journalctl -u corosync -n 100 --no-pager"],
            recovery_hint="Quorum muss wiederhergestellt sein.",
            source="Corosync-Check",
            entity=safe_str(snapshot.get("host"), "host"),
            metric="quorum",
            threshold="quorate",
            current_value=corosync,
            summary="Corosync Problem",
            extra={"raw": corosync},
        ))

    return out
