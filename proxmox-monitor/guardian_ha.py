#!/usr/bin/env python3
from __future__ import annotations

from typing import Any

from guardian_alerts import make_alert
from guardian_helpers import safe_str


def build_ha_alerts(snapshot: dict[str, Any] | None) -> list[dict[str, Any]]:
    snapshot = snapshot or {}
    out: list[dict[str, Any]] = []

    ha = safe_str(snapshot.get("hastatus") or snapshot.get("ha") or "")
    if not ha:
        return out

    up = ha.upper()
    if any(x in up for x in ("ERROR", "FAILED", "CRITICAL", "OFFLINE", "FROZEN")):
        out.append(make_alert(
            category="cluster",
            severity="critical",
            title="HA Problem",
            description="Proxmox HA meldet einen kritischen Zustand.",
            cause=ha,
            solution="HA-Manager, Ressourcen, Knotenstatus und Failover prüfen.",
            diagnosis=["ha-manager status", "systemctl status pve-ha-lrm pve-ha-crm", "journalctl -u pve-ha-lrm -n 100 --no-pager", "journalctl -u pve-ha-crm -n 100 --no-pager"],
            file_path=["/etc/pve/ha", "/var/lib/pve-ha"],
            log_file=["/var/log/syslog", "journalctl -u pve-ha-lrm -n 100 --no-pager", "journalctl -u pve-ha-crm -n 100 --no-pager"],
            recovery_hint="HA muss wieder stabil und quorate sein.",
            source="HA-Check",
            entity=safe_str(snapshot.get("host"), "host"),
            metric="ha",
            threshold="healthy",
            current_value=ha,
            summary="HA Problem",
            extra={"raw": ha},
        ))

    return out
