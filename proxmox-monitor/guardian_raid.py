#!/usr/bin/env python3
from __future__ import annotations

from typing import Any

from guardian_alerts import make_alert
from guardian_helpers import safe_str


def build_raid_alerts(snapshot: dict[str, Any] | None) -> list[dict[str, Any]]:
    snapshot = snapshot or {}
    raid = safe_str(snapshot.get("raidstatus") or snapshot.get("mdstat") or "")
    out: list[dict[str, Any]] = []

    if not raid:
        return out

    up = raid.upper()
    if any(x in up for x in ("DEGRADED", "DEGRADED ARRAY", "FAILED", "FAULT", "OFFLINE", "MISSING", "PRED FAIL", "CRITICAL")):
        out.append(make_alert(
            category="raid",
            severity="critical",
            title="RAID degraded",
            description="Ein RAID-Verbundeintrag meldet einen kritischen Zustand.",
            cause=raid,
            solution="RAID-Status prüfen, betroffene Platte identifizieren, Rebuild/Resync überwachen.",
            diagnosis=["cat /proc/mdstat", "mdadm --detail /dev/mdX", "mdadm --examine /dev/sdX"],
            file_path=["/proc/mdstat", "/etc/mdadm/mdadm.conf"],
            log_file=["/var/log/syslog", "/var/log/kern.log", "journalctl -k -n 200 --no-pager"],
            recovery_hint="RAID muss wieder im optimalen Zustand sein.",
            source="RAID-Check",
            entity=safe_str(snapshot.get("host"), "host"),
            metric="array_health",
            threshold="optimal",
            current_value=raid,
            summary="RAID degraded",
            extra={"raw": raid},
        ))

    if any(x in up for x in ("REBUILD", "RESYNC", "RECOVER")):
        out.append(make_alert(
            category="raid",
            severity="warning",
            title="RAID rebuild läuft",
            description="Ein RAID-Rebuild oder Resync ist aktiv.",
            cause=raid,
            solution="Rebuild beobachten, I/O-Last begrenzen, keine unnötigen Restarts.",
            diagnosis=["cat /proc/mdstat", "mdadm --detail /dev/mdX"],
            file_path=["/proc/mdstat"],
            log_file=["/var/log/syslog", "journalctl -k -n 200 --no-pager"],
            recovery_hint="Rebuild/Resync muss erfolgreich abgeschlossen werden.",
            source="RAID-Rebuild",
            entity=safe_str(snapshot.get("host"), "host"),
            metric="rebuild",
            threshold="completed",
            current_value=raid,
            summary="RAID rebuild",
            extra={"raw": raid},
        ))

    return out
