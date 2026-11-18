#!/usr/bin/env python3
from __future__ import annotations

from typing import Any

from guardian_alerts import make_alert
from guardian_helpers import safe_str


def build_storage_alerts(snapshot: dict[str, Any] | None) -> list[dict[str, Any]]:
    snapshot = snapshot or {}
    out = []

    for storage in snapshot.get("storages", []) or []:

        name = safe_str(storage.get("storage"), "unknown")
        status = safe_str(storage.get("status"), "").lower()
        percent_raw = safe_str(storage.get("percent"), "0").replace("%","")

        try:
            percent = float(percent_raw)
        except Exception:
            percent = 0.0

        if status not in ("available", "active"):
            out.append(make_alert(
                category="storage",
                severity="critical",
                title=f"Storage offline {name}",
                description="Ein Proxmox Storage ist nicht verfügbar.",
                cause=f"Storage={name}, Status={status}",
                solution="Storage-Mount, Netzwerk oder Proxmox Storage-Konfiguration prüfen.",
                diagnosis=[
                    "pvesm status",
                    "cat /etc/pve/storage.cfg",
                    "df -h"
                ],
                file_path=[
                    "/etc/pve/storage.cfg"
                ],
                log_file=[
                    "/var/log/syslog"
                ],
                recovery_hint="Storage muss wieder verfügbar sein.",
                source="Storage Check",
                entity=name,
                metric="status",
                threshold="available",
                current_value=status,
                summary=f"Storage offline {name}"
            ))

        elif percent >= 95:
            out.append(make_alert(
                category="storage",
                severity="critical",
                title=f"Storage kritisch voll {name}",
                description="Ein Storage ist fast vollständig belegt.",
                cause=f"{percent:.1f}% belegt.",
                solution="Nicht benötigte Daten entfernen oder Speicher erweitern.",
                diagnosis=[
                    f"pvesm status",
                    "df -h"
                ],
                file_path=[
                    "/etc/pve/storage.cfg"
                ],
                log_file=[
                    "/var/log/syslog"
                ],
                recovery_hint="Speicherplatz freigeben.",
                source="Storage Check",
                entity=name,
                metric="usage",
                threshold="<95%",
                current_value=f"{percent:.1f}%",
                summary=f"Storage kritisch voll {name}"
            ))

        elif percent >= 85:
            out.append(make_alert(
                category="storage",
                severity="warning",
                title=f"Storage fast voll {name}",
                description="Ein Storage nähert sich der Kapazitätsgrenze.",
                cause=f"{percent:.1f}% belegt.",
                solution="Speicherverbrauch prüfen.",
                diagnosis=[
                    "pvesm status",
                    "df -h"
                ],
                file_path=[
                    "/etc/pve/storage.cfg"
                ],
                log_file=[
                    "/var/log/syslog"
                ],
                recovery_hint="Speicherverbrauch reduzieren.",
                source="Storage Check",
                entity=name,
                metric="usage",
                threshold="<85%",
                current_value=f"{percent:.1f}%",
                summary=f"Storage fast voll {name}"
            ))

    return out
