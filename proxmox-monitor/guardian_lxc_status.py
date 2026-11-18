#!/usr/bin/env python3
from __future__ import annotations

from typing import Any

from guardian_alerts import make_alert
from guardian_guest_stop import build_guest_stop_alerts


def _ct_candidate(vmid: str, name: str, old_status: str, new_status: str) -> dict[str, Any]:
    return make_alert(
        category="lxc_status",
        severity="critical",
        title=f"LXC unerwartet gestoppt: {name}",
        description="Ein laufender Container ist nicht mehr aktiv (kein Stopp-Auftrag in Proxmox gefunden).",
        cause=f"Statuswechsel {old_status} -> {new_status}",
        solution="Containerstatus und Ursache prüfen.",
        diagnosis=[
            f"pct status {vmid}",
            f"pct config {vmid}",
            "journalctl -u pvedaemon -n 100 --no-pager",
        ],
        file_path=[f"/etc/pve/lxc/{vmid}.conf"],
        log_file=["/var/log/syslog"],
        recovery_hint="Container wieder starten oder Ursache beheben.",
        source="LXC Status Check",
        entity=name,
        metric="status",
        threshold="running",
        current_value=new_status,
        summary=f"LXC gestoppt {name}",
    )


def build_lxc_status_alerts(
    old_snapshot: dict[str, Any] | None,
    snapshot: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    return build_guest_stop_alerts("lxc", old_snapshot, snapshot, _ct_candidate)
