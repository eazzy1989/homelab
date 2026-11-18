#!/usr/bin/env python3
from __future__ import annotations

from typing import Any

from guardian_alerts import make_alert
from guardian_helpers import safe_str, clamp_float


def build_pve_alerts(snapshot: dict[str, Any] | None) -> list[dict[str, Any]]:
    snapshot = snapshot or {}
    out: list[dict[str, Any]] = []

    node = safe_str(snapshot.get("node"), "pve")
    host = safe_str(snapshot.get("host"), "Proxmox")

    cpu = clamp_float(snapshot.get("cpu", 0), 0.0, 0.0, 100.0)
    ram = clamp_float(snapshot.get("ram", 0), 0.0, 0.0, 100.0)
    rootfs = snapshot.get("rootfs", {}) or {}
    rootpct = clamp_float(rootfs.get("percent", 0), 0.0, 0.0, 100.0)

    if cpu >= 95:
        out.append(make_alert(
            category="system",
            severity="critical",
            title="CPU kritisch",
            description="Die CPU-Auslastung ist kritisch hoch.",
            cause=f"CPU {cpu:.1f}%.",
            solution="Lastverursacher identifizieren und reduzieren.",
            diagnosis=["top", "htop", "ps -eo pid,ppid,cmd,%cpu --sort=-%cpu | head", "journalctl -n 100 --no-pager"],
            file_path=["/proc", "/etc/pve"],
            log_file=["/var/log/syslog", "journalctl -n 100 --no-pager"],
            recovery_hint="CPU muss wieder unter den kritischen Bereich fallen.",
            source="PVE-Check",
            entity=node,
            metric="cpu",
            threshold="< 95%",
            current_value=f"{cpu:.1f}%",
            summary="CPU kritisch",
        ))

    if ram >= 90:
        out.append(make_alert(
            category="system",
            severity="warning",
            title="RAM hoch",
            description="Die RAM-Auslastung ist hoch.",
            cause=f"RAM {ram:.1f}%.",
            solution="Speicherfresser, Caches und VMs/CTs prüfen.",
            diagnosis=["free -h", "top", "ps aux --sort=-%mem | head", "journalctl -n 100 --no-pager"],
            file_path=["/proc/meminfo", "/etc/pve"],
            log_file=["/var/log/syslog", "journalctl -n 100 --no-pager"],
            recovery_hint="RAM sollte sich wieder entspannen.",
            source="PVE-Check",
            entity=node,
            metric="ram",
            threshold="< 90%",
            current_value=f"{ram:.1f}%",
            summary="RAM hoch",
        ))

    if rootpct >= 95:
        out.append(make_alert(
            category="storage",
            severity="critical",
            title="RootFS kritisch voll",
            description="Das Root-Dateisystem ist kritisch voll.",
            cause=f"RootFS {rootpct:.1f}%.",
            solution="Logs, Backups und temporäre Daten bereinigen.",
            diagnosis=["df -h", "du -xhd1 / | sort -h", "journalctl --disk-usage"],
            file_path=["/", "/var/log", "/etc/pve"],
            log_file=["/var/log/syslog", "journalctl --disk-usage"],
            recovery_hint="RootFS muss wieder freien Platz haben.",
            source="PVE-Check",
            entity=node,
            metric="rootfs",
            threshold="< 95%",
            current_value=f"{rootpct:.1f}%",
            summary="RootFS kritisch voll",
        ))

    if snapshot.get("rebootrequired", False):
        out.append(make_alert(
            category="maintenance",
            severity="warning",
            title="Reboot erforderlich",
            description="Ein Neustart ist nach Updates oder Kernelwechsel empfohlen.",
            cause="reboot-required erkannt.",
            solution="Wartungsfenster für Neustart planen.",
            diagnosis=["needs-restarting -r", "cat /var/run/reboot-required", "uname -r"],
            file_path=["/var/run/reboot-required", "/boot"],
            log_file=["/var/log/apt/history.log", "/var/log/dpkg.log"],
            recovery_hint="Neustart durchführen und System danach erneut prüfen.",
            source="PVE-Check",
            entity=host,
            metric="reboot_required",
            threshold="false",
            current_value="true",
            summary="Reboot erforderlich",
        ))

    nodestatus = snapshot.get("nodestatus", {}) or {}

    node_status = safe_str(nodestatus.get("status"), "").lower()

    if not node_status:
        resources = snapshot.get("node_resources", []) or []
        if resources and isinstance(resources[0], dict):
            node_status = safe_str(resources[0].get("status"), "").lower()

    # 180 Sekunden Grace-Period nach Host-Boot
    try:
        with open("/proc/uptime", "r", encoding="utf-8") as f:
            boot_uptime = float(f.read().split()[0])
    except Exception:
        boot_uptime = 999999

    node_boot_grace = boot_uptime < 180

    if node_status not in ("online", "ok", "running") and not node_boot_grace:
            out.append(make_alert(
                category="cluster",
                severity="critical",
                title="Node problematisch",
                description="Der Proxmox-Node meldet keinen normalen Status.",
                cause=node_status or "unknown",
                solution="Node-Status, Proxmox-Dienste und Clusterkonnektivität prüfen.",
                diagnosis=["pvecm status", "systemctl --failed", "journalctl -u pveproxy -n 100 --no-pager", "journalctl -u pvedaemon -n 100 --no-pager"],
                file_path=["/etc/pve", "/var/lib/pve-cluster"],
                log_file=["/var/log/syslog", "journalctl -u pveproxy -n 100 --no-pager", "journalctl -u pvedaemon -n 100 --no-pager"],
                recovery_hint="Node muss wieder online sein.",
                source="Node-Check",
                entity=node,
                metric="node_status",
                threshold="online/ok/running",
                current_value=safe_str(nodestatus.get("status"), "unknown"),
                summary="Node problematisch",
                extra={"raw": nodestatus},
            ))

    tasks = snapshot.get("tasks", []) or []
    failed = [t for t in tasks if safe_str(t.get("status"), "").lower() in ("error", "failed", "stopped")]
    if failed:
        out.append(make_alert(
            category="tasks",
            severity="warning",
            title="Fehlgeschlagene Tasks",
            description="Es gibt fehlgeschlagene Proxmox-Tasks.",
            cause=f"{len(failed)} Task(s) betroffen.",
            solution="Task-Details und Proxmox-Logs prüfen.",
            diagnosis=["journalctl -u pvedaemon -n 100 --no-pager", "journalctl -u pveproxy -n 100 --no-pager", "pvesh get /nodes/$(hostname -s)/tasks --output-format json"],
            file_path=["/etc/pve"],
            log_file=["/var/log/syslog", "journalctl -u pvedaemon -n 100 --no-pager"],
            recovery_hint="Tasks müssen wieder erfolgreich laufen.",
            source="Task-Check",
            entity=node,
            metric="tasks_failed",
            threshold="0",
            current_value=str(len(failed)),
            summary="Fehlgeschlagene Tasks",
            extra={"tasks": failed[:10]},
        ))

    return out
