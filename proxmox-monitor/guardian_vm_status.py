#!/usr/bin/env python3
from __future__ import annotations

from typing import Any

from guardian_alerts import make_alert
from guardian_guest_stop import build_guest_stop_alerts


def _vm_candidate(vmid: str, name: str, old_status: str, new_status: str) -> dict[str, Any]:
    return make_alert(
        category="vm_status",
        severity="critical",
        title=f"VM unerwartet gestoppt: {name}",
        description="Eine laufende VM ist nicht mehr aktiv (kein Stopp-Auftrag in Proxmox gefunden).",
        cause=f"Statuswechsel {old_status} -> {new_status}",
        solution="VM Status prüfen und Ursache analysieren.",
        diagnosis=[
            f"qm status {vmid}",
            f"qm config {vmid}",
            "journalctl -u pvedaemon -n 100 --no-pager",
        ],
        file_path=[f"/etc/pve/qemu-server/{vmid}.conf"],
        log_file=["/var/log/syslog"],
        recovery_hint="VM wieder starten oder Ursache beheben.",
        source="VM Status Check",
        entity=name,
        metric="status",
        threshold="running",
        current_value=new_status,
        summary=f"VM gestoppt {name}",
    )


def build_vm_status_alerts(
    old_snapshot: dict[str, Any] | None,
    snapshot: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    return build_guest_stop_alerts("qemu", old_snapshot, snapshot, _vm_candidate)
