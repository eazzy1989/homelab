#!/usr/bin/env python3
from __future__ import annotations

from datetime import datetime
from typing import Any

from guardian_alerts import make_alert
from guardian_helpers import safe_str


FAILED_STATUSES = {
    "error",
    "failed",
    "job errors",
}


def _current_guests(snapshot: dict[str, Any]) -> dict[str, str]:
    """Aktuelle QEMU-VMs und LXC dynamisch aus dem Snapshot."""
    guests: dict[str, str] = {}

    for key in ("qemu", "lxc"):
        for guest in snapshot.get(key, []) or []:
            if not isinstance(guest, dict):
                continue

            vmid = safe_str(guest.get("vmid")).strip()
            if not vmid:
                continue

            name = safe_str(
                guest.get("name")
                or guest.get("hostname")
                or f"Guest {vmid}"
            )

            guests[vmid] = name

    return guests


def _backup_jobs(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    """Aktive VZDUMP-Backupjobs dynamisch aus dem Snapshot/API-Datenbestand."""
    jobs = snapshot.get("backup_jobs", []) or []

    if not isinstance(jobs, list):
        return []

    return [
        job for job in jobs
        if isinstance(job, dict)
        and safe_str(job.get("type")).lower() == "vzdump"
        and bool(job.get("enabled", True))
    ]


def _backup_tasks(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    """VZDUMP-Tasks aus dem Snapshot."""
    tasks = snapshot.get("backup_tasks", []) or []

    if not isinstance(tasks, list):
        return []

    return [
        task for task in tasks
        if isinstance(task, dict)
        and safe_str(task.get("type")).lower() == "vzdump"
    ]


def _latest_relevant_task(
    job: dict[str, Any],
    tasks: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """
    Ermittelt den neuesten abgeschlossenen VZDUMP-Lauf.
    Historische Tasks werden nicht pauschal als aktueller Fehler behandelt.
    """
    completed = [
        task for task in tasks
        if task.get("endtime")
        and safe_str(task.get("status")).lower() != "running"
    ]

    if not completed:
        return None

    completed.sort(
        key=lambda task: float(task.get("endtime", 0) or 0),
        reverse=True,
    )

    return completed[0]


def build_backup_alerts(snapshot: dict[str, Any] | None) -> list[dict[str, Any]]:
    snapshot = snapshot or {}
    out: list[dict[str, Any]] = []

    current_guests = _current_guests(snapshot)
    jobs = _backup_jobs(snapshot)
    tasks = _backup_tasks(snapshot)

    # Kein aktiver Backup-Job = kein Backup-Fehler.
    if not jobs:
        return out

    failures: list[str] = []

    for job in jobs:
        task = _latest_relevant_task(job, tasks)

        if not task:
            continue

        status = safe_str(task.get("status")).lower()

        if status not in FAILED_STATUSES:
            continue

        starttime = task.get("starttime")
        timestamp = ""

        if starttime:
            try:
                timestamp = datetime.fromtimestamp(
                    float(starttime)
                ).strftime("%d.%m.%Y %H:%M")
            except Exception:
                pass

        label = safe_str(job.get("id"), "Backup-Job")

        if timestamp:
            failures.append(
                f"{label}: letzter Lauf {timestamp} → "
                f"{safe_str(task.get('status'))}"
            )
        else:
            failures.append(
                f"{label}: {safe_str(task.get('status'))}"
            )

    if failures:
        out.append(make_alert(
            category="backup",
            severity="critical",
            title="Backup fehlgeschlagen",
            description=(
                f"{len(failures)} aktiver Proxmox Backup-Job(s) "
                f"mit fehlgeschlagenem letztem Lauf."
            ),
            cause="\n".join(failures),
            solution=(
                "Den letzten Backup-Lauf prüfen. Die überwachten Gäste "
                "werden automatisch aus dem aktuellen Proxmox-Inventar ermittelt."
            ),
            diagnosis=[
                "pvesh get /cluster/backup --output-format json",
                "pvesh get /nodes/$(hostname -s)/tasks --typefilter vzdump --limit 20 --output-format json",
                "pvesm status",
            ],
            file_path=[
                "/etc/pve/jobs.cfg",
                "/etc/pve/storage.cfg",
            ],
            log_file=[
                "/var/log/syslog",
                "journalctl -u pvedaemon -n 100 --no-pager",
            ],
            recovery_hint=(
                "Nach einem erfolgreichen Backup-Lauf verschwindet "
                "der aktuelle Backup-Fehler automatisch."
            ),
            source="Backup-Task",
            entity="backup",
            metric="status",
            threshold="ok",
            current_value=f"{len(failures)} failed",
            summary="Backup fehlgeschlagen",
        ))

    return out
