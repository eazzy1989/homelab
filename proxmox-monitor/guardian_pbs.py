#!/usr/bin/env python3
from __future__ import annotations

from typing import Any

from guardian_alerts import make_alert
from guardian_helpers import safe_str


def build_pbs_alerts(snapshot: dict[str, Any] | None) -> list[dict[str, Any]]:
    snapshot = snapshot or {}
    out: list[dict[str, Any]] = []

    pbs = snapshot.get("pbsstatus", {}) or {}
    backup_storage = safe_str(pbs.get("backup_storage") or pbs.get("storage") or "")
    pbs_online = bool(pbs.get("online", True))
    last_backup_age = pbs.get("last_backup_age_days")
    failed_backups = pbs.get("failed_backups", 0) or 0

    if backup_storage and not pbs_online:
        out.append(make_alert(
            category="backup",
            severity="critical",
            title="PBS offline",
            description="Proxmox Backup Server oder Backup-Storage ist offline.",
            cause=f"Storage={backup_storage}.",
            solution="PBS-Erreichbarkeit, Netzwerk, Storage-Mount und Auth prüfen.",
            diagnosis=["pvesm status", "ping -c 3 <pbs-host>", "curl -k https://<pbs-host>:8007", "journalctl -u proxmox-backup-proxy -n 100 --no-pager"],
            file_path=["/etc/pve/storage.cfg", "/etc/hosts"],
            log_file=["/var/log/syslog", "journalctl -u proxmox-backup-proxy -n 100 --no-pager"],
            recovery_hint="PBS muss wieder erreichbar sein.",
            source="PBS-Check",
            entity=backup_storage,
            metric="online",
            threshold="true",
            current_value="false",
            summary="PBS offline",
        ))

    if isinstance(last_backup_age, (int, float)) and last_backup_age >= 7:
        out.append(make_alert(
            category="backup",
            severity="warning",
            title="Backup älter als x Tage",
            description="Ein Backup ist älter als der definierte Grenzwert.",
            cause=f"Letztes Backup: {last_backup_age} Tage alt.",
            solution="Backup-Job prüfen, Ziel-Storage und Job-Zeitplan kontrollieren.",
            diagnosis=["pvesh get /cluster/backup", "journalctl -u pvedaemon -n 100 --no-pager", "pvesm status"],
            file_path=["/etc/pve/jobs.cfg", "/etc/pve/storage.cfg"],
            log_file=["/var/log/syslog", "journalctl -u pvedaemon -n 100 --no-pager"],
            recovery_hint="Aktuelles Backup muss erfolgreich laufen.",
            source="PBS-Check",
            entity=backup_storage or "pbs",
            metric="last_backup_age_days",
            threshold="< 7",
            current_value=str(last_backup_age),
            summary="Backup veraltet",
        ))

    if failed_backups and failed_backups > 0:
        out.append(make_alert(
            category="backup",
            severity="critical",
            title="Backup fehlgeschlagen",
            description="Mindestens ein Backup-Job ist fehlgeschlagen.",
            cause=f"Fehlgeschlagene Backups: {failed_backups}.",
            solution="Fehlerhafte Backup-Jobs und Zielsystem prüfen.",
            diagnosis=["pvesh get /cluster/backup", "journalctl -u pvedaemon -n 100 --no-pager", "pvesm status"],
            file_path=["/etc/pve/jobs.cfg", "/etc/pve/storage.cfg"],
            log_file=["/var/log/syslog", "journalctl -u pvedaemon -n 100 --no-pager"],
            recovery_hint="Backups müssen wieder erfolgreich laufen.",
            source="PBS-Check",
            entity=backup_storage or "pbs",
            metric="failed_backups",
            threshold="0",
            current_value=str(failed_backups),
            summary="Backup fehlgeschlagen",
        ))

    return out
