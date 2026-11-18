#!/usr/bin/env python3
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("proxmox_guardian.checks")

from guardian_alerts import make_alert
from guardian_config import CPU_CRIT, CPU_WARN, RAM_CRIT, RAM_WARN, ROOTFS_CRIT, ROOTFS_WARN, NOTIFY_WARNING_CATEGORIES
from guardian_helpers import clamp_float, safe_str
from guardian_network import build_network_alerts
from guardian_storage import build_storage_alerts
from guardian_storage_health import build_storage_health_alerts
from guardian_backup import build_backup_alerts
from guardian_smart import build_smart_alerts
from guardian_zfs import build_zfs_alerts
from guardian_raid import build_raid_alerts
from guardian_security import build_security_alerts
from guardian_pve import build_pve_alerts
from guardian_summary import summarize_guardian
from guardian_dedupe import dedupe_alerts
from guardian_health import build_health_snapshot
from guardian_alerts import run_guardian_alert_engine
from guardian_logs import build_log_alerts
from guardian_api import build_api_alerts
from guardian_vms import build_vm_alerts, build_vm_storage_alerts, build_vm_health_alerts
from guardian_vm_resources import build_vm_resource_alerts
from guardian_vm_status import build_vm_status_alerts
from guardian_replication import build_replication_alerts
from guardian_ha import build_ha_alerts
from guardian_corosync import build_corosync_alerts
from guardian_ceph import build_ceph_alerts
from guardian_pbs import build_pbs_alerts
from guardian_services import build_service_alerts
from guardian_lxc import build_lxc_alerts
from guardian_lxc_status import build_lxc_status_alerts
from guardian_security_ssh import build_ssh_security_alerts


@dataclass
class CheckResult:
    ok: bool
    alert: dict[str, Any] | None = None
    details: dict[str, Any] = field(default_factory=dict)


def _top_cpu(snapshot: dict[str, Any]) -> str:
    items = []
    for vm in snapshot.get("qemu", []) or []:
        items.append(("VM", safe_str(vm.get("name") or vm.get("vmid") or "unknown"), clamp_float(vm.get("cpu", 0.0))))
    for ct in snapshot.get("lxc", []) or []:
        items.append(("LXC", safe_str(ct.get("name") or ct.get("vmid") or "unknown"), clamp_float(ct.get("cpu", 0.0))))
    items.sort(key=lambda x: x[2], reverse=True)
    return ", ".join(f"{k} {n}: {v:.1f}%" for k, n, v in items[:3] if v > 0) or "Kein Verursacher automatisch erkannt"


def _top_ram(snapshot: dict[str, Any]) -> str:
    items = []
    for vm in snapshot.get("qemu", []) or []:
        mem = clamp_float(vm.get("memused", 0.0))
        maxmem = clamp_float(vm.get("memmax", 0.0))
        pct = (mem / maxmem * 100.0) if maxmem > 0 else 0.0
        items.append(("VM", safe_str(vm.get("name") or vm.get("vmid") or "unknown"), pct))
    for ct in snapshot.get("lxc", []) or []:
        mem = clamp_float(ct.get("memused", 0.0))
        maxmem = clamp_float(ct.get("memmax", 0.0))
        pct = (mem / maxmem * 100.0) if maxmem > 0 else 0.0
        items.append(("LXC", safe_str(ct.get("name") or ct.get("vmid") or "unknown"), pct))
    items.sort(key=lambda x: x[2], reverse=True)
    return ", ".join(f"{k} {n}: {v:.1f}%" for k, n, v in items[:3] if v > 0) or "Kein Verursacher automatisch erkannt"


def check_cpu(snapshot):
    cpu = clamp_float(snapshot.get("cpu", 0))
    active = (snapshot.get("guardian_alert_engine", {}) or {}).get("active", {}) or {}
    key = "hardware|CPU-Check|host|cpu|critical"
    if cpu >= CPU_CRIT and key not in active:
        return CheckResult(False, make_alert(category="hardware", severity="critical", title="CPU kritisch", description=f"CPU liegt bei {cpu:.1f} %", cause=f"Top-Verursacher: {_top_cpu(snapshot)}", solution="Lastverursacher prüfen, VMs/Container analysieren, Prozesse begrenzen.", diagnosis=["top", "htop", "ps aux --sort=-%cpu", "qm list", "pct list"], file_path=["/proc/loadavg", "/proc/stat"], log_file=["/var/log/syslog", "/var/log/kern.log", "journalctl -u proxmox-monitor.service -n 100 --no-pager"], recovery_hint="CPU wieder unter Grenzwert.", source="CPU-Check", entity="host", metric="cpu", threshold=f">= {CPU_CRIT}", current_value=f"{cpu:.1f} %", summary="Host CPU kritisch", extra={"top_cpu": _top_cpu(snapshot)}))
    if cpu <= CPU_WARN and key in active:
        return CheckResult(True, make_alert(category="hardware", severity="info", title="CPU wieder normal", description=f"CPU liegt wieder bei {cpu:.1f} %", cause="Lastspitze abgeklungen.", solution="Keine weiteren Maßnahmen notwendig.", diagnosis=["top", "htop"], file_path=["/proc/loadavg", "/proc/stat"], log_file=["/var/log/syslog"], recovery_hint="Keine weiteren Maßnahmen notwendig.", source="CPU-Check", entity="host", metric="cpu", threshold=f"< {CPU_WARN}", current_value=f"{cpu:.1f} %", summary="CPU recovery"))
    return CheckResult(True)


def check_ram(snapshot):
    ram = clamp_float(snapshot.get("ram", 0))
    active = (snapshot.get("guardian_alert_engine", {}) or {}).get("active", {}) or {}
    key = "hardware|RAM-Check|host|ram|critical"
    if ram >= RAM_CRIT and key not in active:
        return CheckResult(False, make_alert(category="hardware", severity="critical", title="RAM kritisch", description=f"RAM liegt bei {ram:.1f} %", cause=f"Top-Verursacher: {_top_ram(snapshot)}", solution="Speichernutzung prüfen, große VMs/Container identifizieren.", diagnosis=["free -m", "cat /proc/meminfo", "ps aux --sort=-%mem", "qm list", "pct list"], file_path=["/proc/meminfo", "/proc/swaps"], log_file=["/var/log/syslog", "journalctl -xe"], recovery_hint="RAM wieder unter Grenzwert.", source="RAM-Check", entity="host", metric="ram", threshold=f">= {RAM_CRIT}", current_value=f"{ram:.1f} %", summary="Host RAM kritisch", extra={"top_ram": _top_ram(snapshot)}))
    if ram <= RAM_WARN and key in active:
        return CheckResult(True, make_alert(category="hardware", severity="info", title="RAM wieder normal", description=f"RAM liegt wieder bei {ram:.1f} %", cause="Lastspitze abgeklungen.", solution="Keine weiteren Maßnahmen notwendig.", diagnosis=["free -m", "cat /proc/meminfo"], file_path=["/proc/meminfo", "/proc/swaps"], log_file=["/var/log/syslog"], recovery_hint="Keine weiteren Maßnahmen notwendig.", source="RAM-Check", entity="host", metric="ram", threshold=f"< {RAM_WARN}", current_value=f"{ram:.1f} %", summary="RAM recovery"))
    return CheckResult(True)


def check_rootfs(snapshot):
    pct = clamp_float(((snapshot.get("rootfs", {}) or {}).get("percent", 0)))
    active = (snapshot.get("guardian_alert_engine", {}) or {}).get("active", {}) or {}
    key = "storage|RootFS-Check|rootfs|percent|critical"
    if pct >= ROOTFS_CRIT and key not in active:
        return CheckResult(False, make_alert(category="storage", severity="critical", title="RootFS kritisch", description=f"RootFS liegt bei {pct:.1f} %", cause="RootFS fast voll.", solution="Nicht benötigte Daten löschen, Logs rotieren, Platz schaffen.", diagnosis=["df -h", "df -i", "du -xhd1 / | sort -h", "pvesm status"], file_path=["/", "/proc/mounts"], log_file=["/var/log/syslog", "/var/log/kern.log", "journalctl -xe"], recovery_hint="RootFS wieder unter Grenzwert.", source="RootFS-Check", entity="rootfs", metric="percent", threshold=f">= {ROOTFS_CRIT}", current_value=f"{pct:.1f} %", summary="RootFS kritisch"))
    if pct <= ROOTFS_WARN and key in active:
        return CheckResult(True, make_alert(category="storage", severity="info", title="RootFS wieder normal", description=f"RootFS liegt wieder bei {pct:.1f} %", cause="Speicherverbrauch gesunken.", solution="Keine weiteren Maßnahmen notwendig.", diagnosis=["df -h", "df -i"], file_path=["/", "/proc/mounts"], log_file=["/var/log/syslog"], recovery_hint="Keine weiteren Maßnahmen notwendig.", source="RootFS-Check", entity="rootfs", metric="percent", threshold=f"< {ROOTFS_WARN}", current_value=f"{pct:.1f} %", summary="RootFS recovery"))
    return CheckResult(True)


def check_reboot_required(snapshot):
    reboot_required = bool(snapshot.get("rebootrequired", False))
    active = (snapshot.get("guardian_alert_engine", {}) or {}).get("active", {}) or {}

    key = "system|Reboot-Check|host|reboot|warning"

    if reboot_required and key not in active:
        kernel = safe_str(snapshot.get("kernel"), "unbekannt")

        return CheckResult(
            False,
            make_alert(
                category="system",
                severity="warning",
                title="Neustart erforderlich",
                description="Ein neuerer Proxmox-Kernel ist installiert als der aktuell laufende Kernel.",
                cause=f"Aktuell laufender Kernel: {kernel}",
                solution="Proxmox neu starten, damit der neue Kernel geladen wird.",
                diagnosis=["uname -r", "ls -1 /boot/vmlinuz-*-pve"],
                file_path=["/boot"],
                log_file=["journalctl -b -0"],
                recovery_hint="Neustart durchführen und den neuen Kernel laden.",
                source="Reboot-Check",
                entity="host",
                metric="reboot",
                threshold="neuerer Kernel installiert",
                current_value=kernel,
                summary="Proxmox-Neustart erforderlich",
                extra={
                    "kernel": kernel,
                    "reboot_required": True,
                },
            ),
        )

    return CheckResult(True)


def build_all_guardian_alerts(snapshot, old_snapshot=None):
    out = []
    for fn in (check_cpu, check_ram, check_rootfs, check_reboot_required):
        try:
            res = fn(snapshot or {})
            if res and res.alert and not res.ok:
                out.append(res.alert)
        except Exception as e:
            # vorher: NameError (extra_builder) -> alle Alarme des Zyklus verloren
            logger.exception("Guardian Check Fehler %s: %s", fn.__name__, e)
            continue

    for extra_builder in (build_network_alerts, build_storage_alerts, build_storage_health_alerts, build_backup_alerts, build_smart_alerts, build_zfs_alerts, build_raid_alerts, build_pbs_alerts, build_ceph_alerts, build_corosync_alerts, build_ha_alerts, build_replication_alerts, build_security_alerts, build_pve_alerts, build_vm_alerts, build_vm_storage_alerts, build_vm_health_alerts, build_vm_resource_alerts, build_lxc_alerts, build_api_alerts, build_log_alerts, build_service_alerts, build_ssh_security_alerts):
        try:
            out.extend(extra_builder(snapshot or {}))
        except Exception as e:
            logger.exception("Guardian Check Fehler %s: %s", extra_builder.__name__, e)
            continue

    try:
        out.extend(
            build_vm_status_alerts(
                old_snapshot or {},
                snapshot or {}
            )
        )
    except Exception as e:
        logger.exception("Guardian Check Fehler build_vm_status_alerts: %s", e)

    try:
        out.extend(
            build_lxc_status_alerts(
                old_snapshot or {},
                snapshot or {}
            )
        )
    except Exception as e:
        logger.exception("Guardian Check Fehler build_lxc_status_alerts: %s", e)

    return out


def build_guardian_bundle(
    old_snapshot: dict[str, Any] | None,
    snapshot: dict[str, Any] | None
) -> tuple[list[dict[str, Any]], dict[str, Any]]:

    old_snapshot = old_snapshot or {}
    snapshot = snapshot or {}

    from monitor import guardian_extract_snapshot

    guardian_input = guardian_extract_snapshot(
        old_snapshot,
        snapshot
    )

    candidates = build_all_guardian_alerts(guardian_input, old_snapshot)
    candidates = dedupe_alerts(candidates)

    outgoing, guardian_snapshot = run_guardian_alert_engine(
        old_snapshot,
        snapshot,
        candidates,
        {
          **guardian_input,
          "guardian_alert_engine": old_snapshot.get("guardian_alert_engine", {}),
          "guardian_meta": old_snapshot.get("guardian_meta", {}),
        },
    )

    logger.debug(
        "CHECKS DEBUG candidates=%d snapshot_candidates=%d outgoing=%d",
        len(candidates),
        len(guardian_snapshot.get("guardian_candidates", []) or []),
        len(outgoing),
    )

    summary = summarize_guardian(snapshot, candidates)

    # Health Score aus den AKTIVEN Alarmen (nach Entprellung), die auch
    # gemeldet werden. Vorher: aus allen Roh-Kandidaten – kurze Spitzen und
    # nie gemeldete Hinweise (z. B. VM-Lock während eines Backups) senkten
    # den Score, ohne dass eine Nachricht kam.
    active = list(((guardian_snapshot.get("guardian_alert_engine") or {}).get("active") or {}).values())
    relevant = [
        a for a in active
        if str(a.get("severity", "")).lower() == "critical"
        or (str(a.get("severity", "")).lower() == "warning"
            and str(a.get("category", "")).lower() in NOTIFY_WARNING_CATEGORIES)
    ]
    health = build_health_snapshot(snapshot, relevant, summary)

    guardian_snapshot["counts"] = health.get(
        "counts",
        {
            "alerts": 0,
            "critical": 0,
            "warning": 0,
        }
    )

    counts = guardian_snapshot["counts"]

    score = 100
    score -= counts.get("critical", 0) * 30
    score -= counts.get("warning", 0) * 10
    score = max(0, score)

    if counts.get("critical", 0) > 0:
        guardian_snapshot["health"] = "critical"
    elif counts.get("warning", 0) > 0:
        guardian_snapshot["health"] = "warning"
    else:
        guardian_snapshot["health"] = "ok"

    guardian_snapshot["health_score"] = score

    guardian_snapshot["summary"] = summary

    guardian_snapshot.update({
        "guardian_health": health,
    })

    return outgoing, guardian_snapshot
