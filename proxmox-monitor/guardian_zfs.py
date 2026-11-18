#!/usr/bin/env python3
from __future__ import annotations

from typing import Any

from guardian_alerts import make_alert
from guardian_helpers import safe_str


def build_zfs_alerts(snapshot: dict[str, Any] | None) -> list[dict[str, Any]]:
    snapshot = snapshot or {}
    zfsstatus = safe_str(snapshot.get("zfsstatus"), "")
    out: list[dict[str, Any]] = []

    if not zfsstatus:
        return out

    up = zfsstatus.upper()
    if any(x in up for x in ("DEGRADED", "FAULTED", "OFFLINE", "UNAVAIL", "SUSPENDED", "CHECKSUM", "READONLY")):
        out.append(make_alert(
            category="zfs",
            severity="critical",
            title="ZFS Pool problematisch",
            description="Ein ZFS-Pool meldet einen kritischen Zustand.",
            cause=zfsstatus,
            solution="Poolzustand prüfen, betroffene Disks identifizieren, Scrub/Resilver überwachen.",
            diagnosis=["zpool status", "zpool list", "zpool events -v", "zpool history"],
            file_path=["/proc/spl/kstat/zfs", "/etc/modprobe.d"],
            log_file=["/var/log/syslog", "/var/log/kern.log", "journalctl -k -n 200 --no-pager"],
            recovery_hint="Pool muss wieder healthy sein und Fehler müssen bereinigt sein.",
            source="ZFS-Check",
            entity=safe_str(snapshot.get("host"), "host"),
            metric="pool_health",
            threshold="healthy",
            current_value=zfsstatus,
            summary="ZFS problematisch",
            extra={"raw": zfsstatus},
        ))

    if "SCRUB" in up and any(x in up for x in ("ERROR", "FAIL", "FAULT", "DEGRAD")):
        out.append(make_alert(
            category="zfs",
            severity="warning",
            title="ZFS Scrub Fehler",
            description="Beim ZFS Scrub wurden Fehler erkannt.",
            cause=zfsstatus,
            solution="zpool status prüfen, betroffene Datenträger und Datenpfade analysieren.",
            diagnosis=["zpool status", "zpool scrub <pool>", "zpool clear <pool>"],
            file_path=["/proc/spl/kstat/zfs"],
            log_file=["/var/log/syslog", "journalctl -k -n 200 --no-pager"],
            recovery_hint="Scrub muss fehlerfrei durchlaufen.",
            source="ZFS-Scrub",
            entity=safe_str(snapshot.get("host"), "host"),
            metric="scrub",
            threshold="0 errors",
            current_value=zfsstatus,
            summary="ZFS Scrub Fehler",
            extra={"raw": zfsstatus},
        ))

    if "CHECKSUM" in up or "CKSUM" in up:
        out.append(make_alert(
            category="zfs",
            severity="critical",
            title="ZFS Checksum Fehler",
            description="Checksum-Fehler wurden im ZFS-Kontext erkannt.",
            cause=zfsstatus,
            solution="Datenintegrität prüfen, betroffene Dateien/Disks identifizieren, Backup validieren.",
            diagnosis=["zpool status", "zpool list", "zpool events -v"],
            file_path=["/proc/spl/kstat/zfs"],
            log_file=["/var/log/syslog", "journalctl -k -n 200 --no-pager"],
            recovery_hint="Keine neuen Checksum-Fehler mehr und Pool gesund.",
            source="ZFS-Checksum",
            entity=safe_str(snapshot.get("host"), "host"),
            metric="checksum",
            threshold="no checksum errors",
            current_value=zfsstatus,
            summary="ZFS Checksum Fehler",
            extra={"raw": zfsstatus},
        ))

    return out
