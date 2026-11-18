#!/usr/bin/env python3
from __future__ import annotations

import time
from typing import Any
from pathlib import Path

from guardian_alerts import make_alert
from guardian_helpers import safe_str, clamp_float


def _read_guest_config(kind: str, vmid: str) -> str:
    """Liest die aktuelle Gast-Konfiguration (ohne Snapshot-Abschnitte).

    Direkt aus /etc/pve statt per `qm config`/`pct config`: spart pro Gast
    und Zyklus einen Perl-Prozess (~0,3-0,5 s CPU). Fallback auf das
    CLI-Werkzeug mit Timeout, falls die Datei nicht lesbar ist.
    """
    import subprocess
    base = "/etc/pve/qemu-server" if kind == "qemu" else "/etc/pve/lxc"
    try:
        text = Path(f"{base}/{vmid}.conf").read_text(encoding="utf-8", errors="ignore")
        current = []
        for line in text.splitlines():
            if line.startswith("["):
                break
            current.append(line)
        return "\n".join(current)
    except Exception:
        pass
    try:
        tool = "qm" if kind == "qemu" else "pct"
        return subprocess.check_output(
            [tool, "config", str(vmid)], text=True, stderr=subprocess.DEVNULL, timeout=15
        )
    except Exception:
        return ""


# pvesm-path-Ergebnisse: erfolgreiche Auflösungen 10 min cachen,
# Fehler werden in jedem Zyklus erneut geprüft.
_PVESM_OK_CACHE: dict[str, float] = {}
_PVESM_OK_TTL = 600


def _lock_line(cfg: str) -> str:
    # Nur die Lock-Zeile in den Alarm übernehmen, nicht die komplette Konfiguration
    for line in (cfg or "").splitlines():
        if line.startswith("lock:"):
            return line.strip()
    return "lock gesetzt"


def _agent_enabled(cfg: str) -> bool:
    import re as _re
    return bool(_re.search(r"^agent:\s*(1\b|enabled=1)", cfg or "", _re.MULTILINE))


def build_vm_alerts(snapshot: dict[str, Any] | None) -> list[dict[str, Any]]:
    snapshot = snapshot or {}
    out: list[dict[str, Any]] = []

    for vm in snapshot.get("qemu", []) or []:
        vmid = safe_str(vm.get("vmid"), "unknown")
        name = safe_str(vm.get("name"), f"vm-{vmid}")
        status = safe_str(vm.get("status"), "unknown").lower()

        cfg = _read_guest_config("qemu", vmid)

        if "lock:" in cfg:
            out.append(make_alert(
                category="vm_health",
                severity="warning",
                title=f"VM Lock aktiv {name}",
                description="Die VM besitzt einen aktiven Proxmox Lock.",
                cause=f"VMID={vmid}, " + _lock_line(cfg),
                solution="Abgebrochenen Task prüfen und Lock entfernen.",
                diagnosis=[
                    f"qm status {vmid}",
                    f"qm unlock {vmid}"
                ],
                file_path=[
                    f"/etc/pve/qemu-server/{vmid}.conf"
                ],
                log_file=[
                    "/var/log/syslog"
                ],
                recovery_hint="Lock nach Ursachenprüfung entfernen.",
                source="VM Health Check",
                entity=name,
                metric="lock",
                threshold="none",
                current_value="locked",
                summary=f"VM Lock aktiv {name}"
            ))

        if status == "running" and not _agent_enabled(cfg):
            out.append(make_alert(
                category="vm_health",
                severity="info",
                title=f"QEMU Agent fehlt {name}",
                description="Die VM läuft ohne QEMU Guest Agent.",
                cause=f"VMID={vmid}: keine agent:1 Konfiguration.",
                solution="Guest Agent installieren und aktivieren.",
                diagnosis=[
                    f"qm config {vmid}",
                    f"qm agent {vmid} ping"
                ],
                file_path=[
                    f"/etc/pve/qemu-server/{vmid}.conf"
                ],
                log_file=[
                    "/var/log/syslog"
                ],
                recovery_hint="Guest Agent aktivieren.",
                source="VM Health Check",
                entity=name,
                metric="guest_agent",
                threshold="enabled",
                current_value="disabled",
                summary=f"QEMU Agent fehlt {name}"
            ))
        cpu = clamp_float(vm.get("cpu", 0), 0.0, 0.0, 100.0)
        memused = clamp_float(vm.get("memused", 0), 0.0, 0.0, 10**18)
        memmax = clamp_float(vm.get("memmax", 0), 0.0, 0.0, 10**18)

        if status not in ("running", "stopped", "paused"):
            out.append(make_alert(
                category="vm",
                severity="warning",
                title=f"QEMU Status auffällig: {name}",
                description="Eine QEMU-VM meldet einen ungewöhnlichen Status.",
                cause=f"VMID={vmid}, Status={status}.",
                solution="VM-Status, Logs und Proxmox-Task-Historie prüfen.",
                diagnosis=[f"qm status {vmid}", f"qm config {vmid}", "journalctl -u pvedaemon -n 100 --no-pager"],
                file_path=["/etc/pve/qemu-server"],
                log_file=["/var/log/syslog", "journalctl -u pvedaemon -n 100 --no-pager"],
                recovery_hint="VM muss wieder in einem erwarteten Zustand sein.",
                source="VM-Check",
                entity=name,
                metric="status",
                threshold="running/stopped/paused",
                current_value=status,
                summary=f"QEMU Status auffällig {name}",
            ))

        if cpu >= 95:
            out.append(make_alert(
                category="vm",
                severity="critical",
                title=f"QEMU CPU kritisch: {name}",
                description="Eine QEMU-VM nutzt extrem viel CPU.",
                cause=f"CPU {cpu:.1f}%.",
                solution="Last, Prozesse und Gastzustand prüfen.",
                diagnosis=[f"qm status {vmid}", f"qm monitor {vmid}", "top"],
                file_path=["/etc/pve/qemu-server"],
                log_file=["/var/log/syslog", "journalctl -u pvedaemon -n 100 --no-pager"],
                recovery_hint="CPU der VM muss sinken.",
                source="VM-Check",
                entity=name,
                metric="cpu",
                threshold="< 95%",
                current_value=f"{cpu:.1f}%",
                summary=f"QEMU CPU kritisch {name}",
            ))

        # Gast-RAM wird nur bewertet, wenn der Snapshot den
        # tatsächlichen Guest-Agent-Wert enthält.
        mem_source = vm.get("mem_source", "proxmox")

        if (
            mem_source == "guest_agent"
            and memmax > 0
            and memused / memmax >= 0.95
        ):
            out.append(make_alert(
                category="vm",
                severity="warning",
                title=f"QEMU RAM hoch: {name}",
                description="Eine QEMU-VM ist fast am RAM-Limit.",
                cause=f"{memused:.0f} / {memmax:.0f}.",
                solution="VM-RAM, Balloning und Gastlast prüfen.",
                diagnosis=[f"qm config {vmid}", f"qm status {vmid}", "free -h"],
                file_path=["/etc/pve/qemu-server"],
                log_file=["/var/log/syslog", "journalctl -u pvedaemon -n 100 --no-pager"],
                recovery_hint="RAM muss wieder unter die Schwelle sinken.",
                source="VM-Check",
                entity=name,
                metric="mem",
                threshold="< 95%",
                current_value=f"{memused:.0f}/{memmax:.0f}",
                summary=f"QEMU RAM hoch {name}",
            ))

    for ct in snapshot.get("lxc", []) or []:
        vmid = safe_str(ct.get("vmid"), "unknown")
        name = safe_str(ct.get("name"), f"ct-{vmid}")
        status = safe_str(ct.get("status"), "unknown").lower()
        cpu = clamp_float(ct.get("cpu", 0), 0.0, 0.0, 100.0)
        memused = clamp_float(ct.get("memused", 0), 0.0, 0.0, 10**18)
        memmax = clamp_float(ct.get("memmax", 0), 0.0, 0.0, 10**18)

        if status not in ("running", "stopped"):
            out.append(make_alert(
                category="ct",
                severity="warning",
                title=f"LXC Status auffällig: {name}",
                description="Ein LXC-Container meldet einen ungewöhnlichen Status.",
                cause=f"CTID={vmid}, Status={status}.",
                solution="Container-Status, Logs und Konfiguration prüfen.",
                diagnosis=[f"pct status {vmid}", f"pct config {vmid}", "journalctl -u pvedaemon -n 100 --no-pager"],
                file_path=["/etc/pve/lxc"],
                log_file=["/var/log/syslog", "journalctl -u pvedaemon -n 100 --no-pager"],
                recovery_hint="Container muss wieder in einem erwarteten Zustand sein.",
                source="CT-Check",
                entity=name,
                metric="status",
                threshold="running/stopped",
                current_value=status,
                summary=f"LXC Status auffällig {name}",
            ))

        if cpu >= 95:
            out.append(make_alert(
                category="ct",
                severity="critical",
                title=f"LXC CPU kritisch: {name}",
                description="Ein Container nutzt extrem viel CPU.",
                cause=f"CPU {cpu:.1f}%.",
                solution="Last, Prozesse und Containerzustand prüfen.",
                diagnosis=[f"pct status {vmid}", f"pct exec {vmid} -- top", "top"],
                file_path=["/etc/pve/lxc"],
                log_file=["/var/log/syslog", "journalctl -u pvedaemon -n 100 --no-pager"],
                recovery_hint="CPU des Containers muss sinken.",
                source="CT-Check",
                entity=name,
                metric="cpu",
                threshold="< 95%",
                current_value=f"{cpu:.1f}%",
                summary=f"LXC CPU kritisch {name}",
            ))

        # Gast-RAM wird nur bewertet, wenn der Snapshot den
        # tatsächlichen Guest-Agent-Wert enthält.
        mem_source = vm.get("mem_source", "proxmox")

        if (
            mem_source == "guest_agent"
            and memmax > 0
            and memused / memmax >= 0.95
        ):
            out.append(make_alert(
                category="ct",
                severity="warning",
                title=f"LXC RAM hoch: {name}",
                description="Ein Container ist fast am RAM-Limit.",
                cause=f"{memused:.0f} / {memmax:.0f}.",
                solution="Container-RAM und Gastlast prüfen.",
                diagnosis=[f"pct config {vmid}", f"pct status {vmid}", "free -h"],
                file_path=["/etc/pve/lxc"],
                log_file=["/var/log/syslog", "journalctl -u pvedaemon -n 100 --no-pager"],
                recovery_hint="RAM muss wieder unter die Schwelle sinken.",
                source="CT-Check",
                entity=name,
                metric="mem",
                threshold="< 95%",
                current_value=f"{memused:.0f}/{memmax:.0f}",
                summary=f"LXC RAM hoch {name}",
            ))

    return out






def build_vm_storage_alerts(snapshot: dict[str, Any] | None) -> list[dict[str, Any]]:
    snapshot = snapshot or {}
    out = []

    import subprocess
    from pathlib import Path

    for vm in snapshot.get("qemu", []) or []:
        vmid = str(vm.get("vmid"))
        vmname = str(vm.get("name") or f"vm-{vmid}")

        cfg_path = Path(f"/etc/pve/qemu-server/{vmid}.conf")

        try:
            cfg = cfg_path.read_text()
        except Exception:
            continue

        for line in cfg.splitlines():

            if not line.startswith(
                (
                    "scsi",
                    "virtio",
                    "sata",
                    "ide",
                    "efidisk",
                    "tpmstate",
                )
            ):
                continue

            # Controller-Zeilen ignorieren
            if line.startswith("scsihw"):
                continue

            if ":" not in line:
                continue

            key, value = line.split(":", 1)
            value = value.strip()

            # CD-ROM / none ignorieren
            if value.startswith("none"):
                continue

            # ISO/CDROM ignorieren
            if ",media=cdrom" in value:
                continue

            volume = value.split(",", 1)[0]

            # Nur Proxmox Storage Volumes prüfen
            if ":" not in volume:
                continue

            if _PVESM_OK_CACHE.get(volume, 0) > time.time():
                continue

            try:
                result = subprocess.run(
                    [
                        "pvesm",
                        "path",
                        volume
                    ],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    _PVESM_OK_CACHE[volume] = time.time() + _PVESM_OK_TTL

                if result.returncode != 0:
                    out.append(make_alert(
                        category="vm_storage",
                        severity="critical",
                        title=f"VM Disk fehlt {vmid} ({vmname})",
                        description="Ein konfiguriertes VM Volume konnte nicht aufgelöst werden.",
                        cause=f"Volume {volume} nicht erreichbar.",
                        solution="VM-Konfiguration und Storage prüfen.",
                        diagnosis=[
                            f"qm config {vmid}",
                            f"pvesm path {volume}",
                            "pvesm status"
                        ],
                        file_path=[
                            f"/etc/pve/qemu-server/{vmid}.conf"
                        ],
                        log_file=[
                            "/var/log/syslog"
                        ],
                        recovery_hint="Volume wiederherstellen oder VM-Konfiguration korrigieren.",
                        source="VM Storage Check",
                        entity=vmname,
                        metric="disk",
                        threshold="volume exists",
                        current_value=volume,
                        summary=f"VM Disk fehlt {vmid}",
                    ))

            except Exception:
                continue

    return out

def build_vm_health_alerts(snapshot: dict[str, Any] | None) -> list[dict[str, Any]]:
    snapshot = snapshot or {}
    out = []

    for vm in snapshot.get("qemu", []) or []:
        vmid = safe_str(vm.get("vmid"), "unknown")
        name = safe_str(vm.get("name"), f"vm-{vmid}")
        status = safe_str(vm.get("status"), "unknown").lower()

        if status not in ("running", "stopped"):
            out.append(make_alert(
                category="vm_health",
                severity="warning",
                title=f"VM Status auffällig {name}",
                description="QEMU VM meldet einen unerwarteten Status.",
                cause=f"VMID={vmid}, Status={status}",
                solution="VM Status und Proxmox Tasks prüfen.",
                diagnosis=[
                    f"qm status {vmid}",
                    f"qm config {vmid}",
                    "pvesh get /nodes/$(hostname -s)/tasks --output-format json"
                ],
                file_path=["/etc/pve/qemu-server"],
                log_file=["/var/log/syslog"],
                recovery_hint="VM wieder in einen normalen Zustand bringen.",
                source="VM Health Check",
                entity=name,
                metric="status",
                threshold="running/stopped",
                current_value=status,
                summary=f"VM Status auffällig {name}",
            ))

    for ct in snapshot.get("lxc", []) or []:
        vmid = safe_str(ct.get("vmid"), "unknown")
        name = safe_str(ct.get("name"), f"ct-{vmid}")
        status = safe_str(ct.get("status"), "unknown").lower()

        cfg = _read_guest_config("lxc", vmid)

        if "lock:" in cfg:
            out.append(make_alert(
                category="ct_health",
                severity="warning",
                title=f"LXC Lock aktiv {name}",
                description="Der Container besitzt einen aktiven Proxmox Lock.",
                cause=f"CTID={vmid}, " + _lock_line(cfg),
                solution="Abgebrochenen Task prüfen und Lock entfernen.",
                diagnosis=[
                    f"pct status {vmid}",
                    f"pct unlock {vmid}"
                ],
                file_path=[
                    f"/etc/pve/lxc/{vmid}.conf"
                ],
                log_file=[
                    "/var/log/syslog"
                ],
                recovery_hint="Lock nach Ursachenprüfung entfernen.",
                source="CT Health Check",
                entity=name,
                metric="lock",
                threshold="none",
                current_value="locked",
                summary=f"LXC Lock aktiv {name}"
            ))

        if status not in ("running", "stopped"):
            out.append(make_alert(
                category="ct_health",
                severity="warning",
                title=f"LXC Status auffällig {name}",
                description="LXC Container meldet einen unerwarteten Status.",
                cause=f"CTID={vmid}, Status={status}",
                solution="Container Status und Logs prüfen.",
                diagnosis=[
                    f"pct status {vmid}",
                    f"pct config {vmid}"
                ],
                file_path=["/etc/pve/lxc"],
                log_file=["/var/log/syslog"],
                recovery_hint="Container wiederherstellen.",
                source="CT Health Check",
                entity=name,
                metric="status",
                threshold="running/stopped",
                current_value=status,
                summary=f"LXC Status auffällig {name}",
            ))

    return out
