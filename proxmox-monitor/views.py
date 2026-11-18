import os
import subprocess
from pathlib import Path
from datetime import datetime
import time
from typing import Any

from utils import (
    fmt_gb,
    format_uptime_seconds,
    _detect_node,
    ping_target,
    _run_cmd,
    _json_cmd,
    _fmt_bytes,
    _fmt_pct,
    _fmt_duration,
    _parse_table_lines,
    _list_running_tasks,
    _list_failed_tasks,
    tcp_port_check,
    _parse_backup_storages,
    _extract_guest_from_volid,
    _count_backups_for_storage,
    _read_first_existing,
)
import html as _html

HOST_LABEL = "Proxmox Guardian"
PROXMOX_NODE = "pve"
MAX_SENSORS = 10
MAX_LOG_LINES = 15
# fehlten bisher -> NameError in format_alerts, sobald Alarme aktiv waren
MAX_ALERTS_ACTIVE = 15
MAX_ALERTS_RECOVERED = 10
LOG_FILE = Path(os.getenv("MONITOR_BASE_DIR", Path(__file__).resolve().parent)) / "logs" / "monitor.log"

Snapshot = dict[str, Any]


def _msg_title(icon: str, title: str) -> list[str]:
    return [
        f"{icon} {title}",
        "────────────────────────────────",
        "",
    ]


def _msg_section(lines: list[str], title: str, rows: list[str]) -> None:
    lines.append(title)
    lines.extend(rows)
    lines.append("")


def _msg_kv(label: str, value, prefix: str = "•") -> str:
    return f"{prefix} {label}: {value}"


def _msg_footer(snapshot=None, label: str = "Letzte Prüfung") -> list[str]:
    if isinstance(snapshot, dict):
        return [f"{label}: {snapshot.get('last_check', 'unbekannt')}"]
    return [f"{label}: unbekannt"]


def _clean_join(lines: list[str]) -> str:
    return "\n".join(lines)


def overall_status(snapshot):
    raw_health = _health_percent(snapshot)
    try:
        health = int(float(raw_health))
    except (TypeError, ValueError):
        health = 0
    if health >= 90:
        return "🟢 OK"
    if health >= 70:
        return "🟡 WARN"
    return "🔴 CRITICAL"

def _health_percent(snapshot):
    if not isinstance(snapshot, dict):
        return "n/a"
    for key in ("health_score", "score", "health"):
        raw = snapshot.get(key)
        try:
            return str(int(float(raw)))
        except (TypeError, ValueError):
            pass
    return "n/a"


def _health_state(snapshot):
    """Zeigt einen echten Zustandsstatus anhand der erkannten Alerts."""
    alerts = snapshot.get("alerts", []) or []

    active = []
    for alert in alerts:
        if isinstance(alert, dict):
            if not alert.get("recovered"):
                active.append(alert)
        elif not str(alert).startswith("✅"):
            active.append(alert)

    critical = any(
        isinstance(a, dict) and str(a.get("severity", "")).lower() == "critical"
        for a in active
    )
    warning = any(
        isinstance(a, dict) and str(a.get("severity", "")).lower() == "warning"
        for a in active
    )

    if critical:
        return "🔴 KRITISCH"
    if warning:
        return "🟡 WARNUNG"
    return "🟢 OK"



def format_home(snapshot: Snapshot) -> str:
    alerts = snapshot.get("alerts", []) or []
    active = [a for a in alerts if isinstance(a, dict) and not a.get("recovered")]
    recovered = [a for a in alerts if isinstance(a, dict) and a.get("recovered")]

    def short_alert(a):
        title = str(a.get("title", "")).strip()
        detail_lines = str(a.get("details", "")).strip().splitlines()
        details = detail_lines[0][:38] if detail_lines else ""
        source = str(a.get("source", "")).strip()[:16]
        line = title[:46] if title else "Unbekannter Alert"
        if details:
            line += f" — {details}"
        elif source:
            line += f" — {source}"
        return f"• {line}"

    top = active[:5] if active else recovered[:3]
    top_lines = [short_alert(a) for a in top] if top else ["• Keine aktiven Warnungen"]

    internet = "Online" if snapshot.get("internet_online", False) else "Offline"
    dns = "OK" if snapshot.get("dns_ok", False) else "Fehler"
    telegram = "OK" if snapshot.get("telegram_online", False) else "Fehler"
    reboot = "Ja" if snapshot.get("reboot_required", False) else "Nein"

    qemu = snapshot.get("qemu", []) or []
    lxc = snapshot.get("lxc", []) or []
    qemu_running = sum(1 for x in qemu if str(x.get("status", "")).lower() == "running")
    lxc_running = sum(1 for x in lxc if str(x.get("status", "")).lower() == "running")

    table = [
        "ÜBERBLICK",
        f"{'Host':<10} {str(snapshot.get('host', HOST_LABEL))[:18]:<18}",
        f"{'Node':<10} {str(snapshot.get('node', PROXMOX_NODE))[:18]:<18}",
        f"{'Health':<10} {_health_state(snapshot)}",
        f"{'CPU':<10} {snapshot.get('cpu', 0)} %",
        f"{'RAM':<10} {snapshot.get('ram', 0)} %",
        f"{'Load':<10} {snapshot.get('load1', 0):.2f}/{snapshot.get('load5', 0):.2f}/{snapshot.get('load15', 0):.2f}",
        f"{'IO-Wait':<10} {snapshot.get('io_wait', 0):.2f} %",
        f"{'Swap':<10} {snapshot.get('swap_percent', 0):.1f} %",
        f"{'RootFS':<10} {snapshot.get('rootfs', {}).get('percent', 0)} %",
        f"{'Internet':<10} {internet}",
        f"{'DNS':<10} {dns}",
        f"{'Telegram':<10} {telegram}",
        f"{'Reboot':<10} {reboot}",
        f"{'QEMU':<10} {qemu_running}/{len(qemu)} online",
        f"{'LXC':<10} {lxc_running}/{len(lxc)} online",
        f"{'Storages':<10} {len(snapshot.get('storages', []))}",
        f"{'Aktiv':<10} {len(active)}",
        f"{'Recovery':<10} {len(recovered)}",
        "",
        "TOP-EREIGNISSE",
        *top_lines,
        "",
        f"Letzte Prüfung: {snapshot.get('last_check', 'unbekannt')}",
    ]

    return "\n".join([
        f"🤖 {snapshot.get('host', HOST_LABEL)}",
        "────────────────────────────────",
        "",
        f"<pre>{chr(10).join(table)}</pre>",
    ])


def format_host(snapshot: Snapshot) -> str:
    version = snapshot.get("version", {}) or {}
    node_status = snapshot.get("node_status", {}) or {}
    cpuinfo = (
        node_status.get("cpuinfo", {})
        if isinstance(node_status.get("cpuinfo", {}), dict)
        else {}
    )
    rootfs = snapshot.get("rootfs", {}) or {}

    host = str(snapshot.get("hostname", "unbekannt"))
    node = str(snapshot.get("node", PROXMOX_NODE))
    proxmox_version = str(
        version.get("release", version.get("version", "unbekannt"))
    )
    kernel = str(snapshot.get("kernel", "unbekannt"))[:24]
    cpu_model = str(
        cpuinfo.get("model", node_status.get("cpu", "unbekannt"))
    )[:30]
    cpu_cores = cpuinfo.get(
        "cores",
        node_status.get("cpuinfo", {}).get("cores")
        if isinstance(node_status.get("cpuinfo", {}), dict)
        else "unbekannt",
    )

    reboot = "Ja" if snapshot.get("reboot_required", False) else "Nein"
    cpu = snapshot.get("cpu", 0)
    ram = snapshot.get("ram", 0)
    load = (
        f"{snapshot.get('load1', 0)}/"
        f"{snapshot.get('load5', 0)}/"
        f"{snapshot.get('load15', 0)}"
    )
    temp = snapshot.get("cpu_temp", "n/a")
    uptime = str(snapshot.get("uptime", "unbekannt"))[:24]

    table = [
        "BEREICH                WERT",
        f"Host                   {host}",
        f"Node                   {node}",
        f"PVE                    {proxmox_version}",
        f"Kernel                 {kernel}",
        f"CPU                    {cpu_model}",
        f"CPU-Kerne              {cpu_cores}",
        f"CPU-Auslastung         {cpu} %",
        f"RAM-Auslastung         {ram} %",
        f"RootFS                 {rootfs.get('percent', 0)} %",
        f"Load                   {load}",
        f"Temperatur             {temp} C" if temp != "n/a" else "Temperatur             n/a",
        f"Uptime                 {uptime}",
        f"Reboot nötig           {reboot}",
    ]

    smart_items = snapshot.get("smart", [])[:5]
    table.append("")
    table.append("SMART                   STATUS")

    if smart_items:
        for d in smart_items:
            device = str(d.get("device", "?"))[:20]
            health = str(d.get("health", "unbekannt"))
            health = health.replace(
                "SMART overall-health self-assessment test result: ",
                ""
            )
            table.append(f"{device:<22} {health[:30]}")
    else:
        table.append("Keine SMART-Daten")

    table.append("")
    table.append("ZFS                     STATUS")
    table.append(str(snapshot.get(
        "zfs_status",
        "Kein ZFS oder nicht verfügbar"
    ))[:55])

    return "\n".join([
        "🖥 Host",
        "────────────────────────────────",
        "",
        f"<pre>{chr(10).join(table)}</pre>",
    ])

def format_status(snapshot: Snapshot) -> str:
    qemus = snapshot.get("qemu", [])
    lxcs = snapshot.get("lxc", [])
    storages = snapshot.get("storages", [])
    alerts = snapshot.get("alerts", [])
    rootfs = snapshot.get("rootfs", {}) or {}

    qemu_running = sum(1 for vm in qemus if vm.get("status") == "running")
    lxc_running = sum(1 for ct in lxcs if ct.get("status") == "running")
    active_alerts = [
        a for a in alerts
        if (isinstance(a, dict) and not a.get("recovered")) or (not isinstance(a, dict) and not str(a).startswith("✅"))
    ]

    local_ip = str(snapshot.get("lan_ip", snapshot.get("local_ip", "unbekannt")))
    wan_ip = str(snapshot.get("wan_ip", "unbekannt"))
    kernel = str(snapshot.get("kernel", "unbekannt"))[:18]
    uptime = str(snapshot.get("uptime", "unbekannt"))[:18]
    load = f"{snapshot.get('load1', 0)}/{snapshot.get('load5', 0)}/{snapshot.get('load15', 0)}"
    reboot = "Ja" if snapshot.get("reboot_required", False) else "Nein"
    temp = snapshot.get("cpu_temp", "n/a")
    health = _health_state(snapshot)

    left = [
        ("Node", snapshot.get("node", PROXMOX_NODE)),
        ("Host", snapshot.get("hostname", "unbekannt")),
        ("Kernel", kernel),
        ("Uptime", uptime),
        ("Reboot", reboot),
        ("Health", health),
    ]

    io_wait = float(snapshot.get("io_wait", 0) or 0)
    swap_percent = float(snapshot.get("swap_percent", 0) or 0)
    swap_used = float(snapshot.get("swap_used", 0) or 0)
    swap_total = float(snapshot.get("swap_total", 0) or 0)

    swap_used_gb = swap_used / (1024 ** 3)
    swap_total_gb = swap_total / (1024 ** 3)

    right = [
        ("RootFS", f"{rootfs.get('percent', 0)}%"),
        ("Disk", f"{rootfs.get('used_gb', 0)}G/{rootfs.get('total_gb', 0)}G"),
        ("Temp", f"{temp}C" if temp != "n/a" else "n/a"),
    ]

    left2 = [
        ("QEMU", f"{qemu_running}/{len(qemus)}"),
        ("LXC", f"{lxc_running}/{len(lxcs)}"),
        ("Store", len(storages)),
        ("Alerts", len(active_alerts)),
    ]

    # Alle VMs/LXCs dynamisch anzeigen.
    # Die Daten stammen direkt aus Proxmox /cluster/resources.
    guest_lines = []

    guests = []
    for vm in qemus:
        guests.append(("VM", vm))
    for ct in lxcs:
        guests.append(("LXC", ct))

    guests.sort(key=lambda item: int(item[1].get("vmid", 0) or 0))

    for kind, guest in guests:
        vmid = str(guest.get("vmid", "?"))
        name = str(
            guest.get("name")
            or guest.get("hostname")
            or f"{kind} {vmid}"
        )
        status = str(guest.get("status", "unknown")).lower()

        if status == "running":
            cpu = float(guest.get("cpu", 0) or 0)
            mem_used = float(guest.get("mem_used", 0) or 0)
            mem_max = float(guest.get("mem_max", 0) or 0)

            mem_gb = mem_used / (1024 ** 3)
            maxmem_gb = mem_max / (1024 ** 3)

            if maxmem_gb > 0:
                mem_text = f"{mem_gb:.2f}/{maxmem_gb:.2f}G"
            else:
                mem_text = f"{mem_gb:.2f}G"

            guest_lines.append(
                f"{kind:<4} {vmid:<4} {name[:18]:<18} "
                f"CPU {cpu:>5.1f}%  RAM {mem_text}"
            )
        else:
            guest_lines.append(
                f"{kind:<4} {vmid:<4} {name[:18]:<18} AUS"
            )

    right2 = [
        ("Netz", "Online" if snapshot.get("internet_online", False) else "Offline"),
        ("TG API", "OK" if snapshot.get("telegram_online", False) else "Fail"),
        ("DNS", "OK" if snapshot.get("dns_ok", False) else "Fail"),
        ("LAN", local_ip[:18]),
        ("WAN", wan_ip[:18]),
    ]

    table = []
    table.append("SYSTEM                RESSOURCEN")
    for i in range(max(len(left), len(right))):
        l = left[i] if i < len(left) else ("", "")
        r = right[i] if i < len(right) else ("", "")
        table.append(f"{l[0]:<7} {str(l[1]):<12}   {r[0]:<7} {str(r[1]):<12}")

    table.append("")
    table.append("GÄSTE                 NETZWERK")
    for i in range(max(len(left2), len(right2))):
        l = left2[i] if i < len(left2) else ("", "")
        r = right2[i] if i < len(right2) else ("", "")
        table.append(f"{l[0]:<7} {str(l[1]):<12}   {r[0]:<7} {str(r[1]):<12}")

    table.append("")
    table.append("GÄSTE")
    table.append("")
    table.append(f"{'VMID':<6} {'NAME':<18} {'CPU':>7} {'RAM':>12}")
    table.append(f"{'-'*6} {'-'*18} {'-'*7} {'-'*12}")
    
    for kind, guest in guests:
        vmid = str(guest.get("vmid", "?"))
        name = str(guest.get("name") or guest.get("hostname") or f"{kind} {vmid}")[:18]
        status = str(guest.get("status", "unknown")).lower()

        if status == "running":
            cpu = float(guest.get("cpu", 0) or 0)
            mem_used = float(guest.get("mem_used", 0) or 0)
            mem_max = float(guest.get("mem_max", 0) or 0)

            mem_gb = mem_used / (1024 ** 3)
            maxmem_gb = mem_max / (1024 ** 3)

            cpu_text = f"{cpu:.1f}%"
            ram_text = f"{mem_gb:.2f}/{maxmem_gb:.2f}G"
        else:
            cpu_text = "AUS"
            ram_text = "-"

        table.append(
            f"{vmid:<6} {name:<18} {cpu_text:>7} {ram_text:>12}"
        )

    return "\n".join([
        "📊 Status",
        "────────────────────────────────",
        "",
        f"<pre>{chr(10).join(table)}</pre>",
    ])

    lines = [
        f"📊 Status — {snapshot.get('host', HOST_LABEL)}",
        "",
        f"{overall_status(snapshot)}",
        f"Health: {_health_state(snapshot)}",
        "",
        f"<pre>{chr(10).join(table)}</pre>",
        "",
        f"🕒 Letzte Prüfung: {snapshot.get('last_check', 'unbekannt')}",
    ]
    return "\n".join(lines)





def format_guests(snapshot: Snapshot, key: str, title: str, icon: str) -> str:
    items = snapshot.get(key, []) or []

    running = []
    stopped = []

    for item in items:
        kind = "VM" if key == "qemu" else "LXC"
        name = str(item.get("name", f"{kind} {item.get('vmid')}"))[:18]
        vmid = str(item.get("vmid", "?"))

        status = str(item.get("status", "unknown")).lower()
        cpu = round(float(item.get("cpu", 0) or 0), 1)

        maxmem = float(item.get("mem_max", 0) or 0)
        mem = float(item.get("mem_used", 0) or 0)
        rampct = round(mem / maxmem * 100, 1) if maxmem else 0.0
        uptime = format_uptime_seconds(item.get("uptime", 0))

        if status == "running":
            running.append((
                cpu,
                vmid,
                name,
                f"{cpu:.1f}%",
                f"{rampct:.1f}%",
                uptime,
            ))
        else:
            state = (
                "stopped"
                if status in ("stopped", "stop")
                else status[:12]
            )
            stopped.append((vmid, name, state))

    running.sort(key=lambda x: x[0], reverse=True)
    stopped.sort()

    table = [
        "ÜBERSICHT              WERT",
        f"Gesamt                 {len(items)}",
        f"Online                 {len(running)}",
        f"Offline                {len(stopped)}",
        "",
        "AKTIV",
        "VMID   NAME                 CPU      RAM      UPTIME",
    ]

    if running:
        for _, vmid, name, cpu, ram, uptime in running:
            table.append(
                f"{vmid:<6} {name:<20} {cpu:>7} {ram:>8} {uptime:<10}"
            )
    else:
        table.append("Keine laufenden Einträge")

    table.append("")
    table.append("INAKTIV")
    table.append("VMID   NAME                 STATUS")

    if stopped:
        for vmid, name, state in stopped:
            table.append(f"{vmid:<6} {name:<20} {state}")
    else:
        table.append("Keine gestoppten Einträge")

    table.append("")
    table.append(
        f"Snapshot               {snapshot.get('last_check', 'unbekannt')}"
    )

    return "\n".join([
        f"{icon} {title}",
        "────────────────────────────────",
        "",
        f"<pre>{chr(10).join(table)}</pre>",
    ])

def format_qemu(snapshot: Snapshot) -> str:
    return format_guests(snapshot, "qemu", "QEMU VMs", "🖥")

def format_lxc(snapshot: Snapshot) -> str:
    return format_guests(snapshot, "lxc", "LXC Container", "📦")


def format_updates(snapshot: Snapshot) -> str:
    apt = snapshot.get("apt_updates", {}) or {}

    available = int(apt.get("available", 0) or 0)
    security = int(apt.get("security", 0) or 0)

    reboot = "Ja" if snapshot.get("reboot_required", False) else "Nein"
    kernel = str(snapshot.get("kernel", "unbekannt"))[:24]

    table = [
        "UPDATES",
        f"{'Verfügbar':<12} {available:<18}",
        f"{'Security':<12} {security:<18}",
        f"{'Kernel':<12} {kernel:<18}",
        f"{'Reboot':<12} {reboot:<18}",
        f"Letzte Prüfung: {snapshot.get('last_check', 'unbekannt')}",
    ]

    return "\n".join([
        "📦 Updates",
        "────────────────────────────────",
        "",
        f"<pre>{chr(10).join(table)}</pre>",
    ])


def format_disk(snapshot: Snapshot) -> str:
    rootfs = snapshot.get("rootfs", {}) or {}
    storages = snapshot.get("storages", []) or []

    table = [
        "BEREICH                WERT",
        f"RootFS                 {rootfs.get('percent', 'n/a')} %",
        f"Belegt                 {rootfs.get('used_gb', 'n/a')} G",
        f"Frei                   {rootfs.get('free_gb', 'n/a')} G",
        f"Gesamt                 {rootfs.get('total_gb', 'n/a')} G",
    ]

    if storages:
        table.append("")
        table.append("STORAGE                AUSLASTUNG / STATUS")

        for st in storages[:15]:
            name = str(st.get("storage", "unknown"))[:20]
            pct = str(st.get("percent", "0%"))
            used = round((st.get("used", 0) or 0) / (1024 ** 3), 1)
            avail = round((st.get("avail", 0) or 0) / (1024 ** 3), 1)
            status = str(st.get("status", "unknown"))
            table.append(
                f"{name:<22} {pct:<7} {used}G genutzt / {avail}G frei / {status}"
            )
    else:
        table.append("")
        table.append("Keine Storage-Daten verfügbar.")

    table.append("")
    table.append(
        f"Snapshot               {snapshot.get('last_check', 'unbekannt')}"
    )

    return "\n".join([
        "💽 Disk",
        "────────────────────────────────",
        "",
        f"<pre>{chr(10).join(table)}</pre>",
    ])


def format_smart(snapshot: Snapshot) -> str:
    smart = snapshot.get("smart", []) or []

    def norm_health(value):
        raw = str(value or "n/a").strip()
        short = raw.replace(
            "SMART overall-health self-assessment test result:",
            ""
        ).strip()

        upper = short.upper()

        if upper in ("PASSED", "OK"):
            return "OK"
        if upper in ("FAILED", "FAIL"):
            return "FAIL"
        if upper in ("N/A", "NA", "UNKNOWN", ""):
            return "n/a"
        return short[:12]

    table = [
        "DEVICE                STATUS       TEMP      MODEL"
    ]

    if not smart:
        table.append("Keine SMART-Daten verfügbar.")
    else:
        for d in smart[:20]:
            dev = str(d.get("device", "unbekannt"))[:20]
            health = norm_health(d.get("health", "n/a"))
            temp = str(d.get("temp", "n/a"))
            temp_text = (
                f"{temp} C"
                if temp not in ("", "n/a", "None")
                else "n/a"
            )
            model = str(d.get("model", ""))[:22]

            table.append(
                f"{dev:<20} {health:<11} {temp_text:<9} {model}"
            )

    table.append("")
    table.append(
        f"Snapshot              {snapshot.get('last_check', 'unbekannt')}"
    )

    return "\n".join([
        "💿 SMART",
        "────────────────────────────────",
        "",
        f"<pre>{chr(10).join(table)}</pre>",
    ])


def format_ping(snapshot: Snapshot) -> str:
    # Ziele kommen aus der .env:
    #   PING_TARGETS=1.1.1.1,8.8.8.8,api.telegram.org,192.168.1.1
    #   PORT_CHECKS=Webserver:192.168.1.20:443,NAS:192.168.1.30:445
    host_targets = [
        x.strip() for x in os.getenv("PING_TARGETS", "1.1.1.1,8.8.8.8,api.telegram.org").split(",") if x.strip()
    ]

    port_targets = []
    for entry in os.getenv("PORT_CHECKS", "").split(","):
        parts = entry.strip().rsplit(":", 2)
        if len(parts) == 3 and parts[2].isdigit():
            port_targets.append((parts[0], parts[1], int(parts[2])))

    try:
        proc = subprocess.run(
            ["ss", "-lnt"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=3,
            check=False,
        )

        seen = {(host, port) for _, host, port in port_targets}

        for line in (proc.stdout or "").splitlines():
            parts = line.split()

            if len(parts) < 4 or parts[0] != "LISTEN":
                continue

            local = parts[3]

            if local.startswith("["):
                if "]:" not in local:
                    continue
                host, port_text = local.rsplit(":", 1)
                host = host.strip("[]")
            else:
                host, sep, port_text = local.rpartition(":")
                if not sep:
                    continue

            if not port_text.isdigit():
                continue

            port = int(port_text)

            if port not in (22, 3128, 8006):
                continue

            target_host = "127.0.0.1"
            key = (target_host, port)

            if key in seen:
                continue

            port_targets.append(
                (f"Proxmox:{port}", target_host, port)
            )
            seen.add(key)

    except Exception:
        pass

    host_ok = 0
    port_ok = 0

    table = [
        "ZIEL                  STATUS       LATENZ"
    ]

    for target in host_targets:
        result = ping_target(target)

        if result["ok"] and result["latency_ms"] is not None:
            status = "OK"
            latency = f"{result['latency_ms']:.1f} ms"
            host_ok += 1
        elif result["ok"]:
            status = "OK"
            latency = "erreichbar"
            host_ok += 1
        else:
            status = "FAIL"
            latency = "timeout"

        table.append(
            f"{target[:20]:<20} {status:<11} {latency}"
        )

    table.append("")

    for label, host, port in port_targets[:20]:
        result = tcp_port_check(host, port)

        if result["ok"] and result["latency_ms"] is not None:
            status = "OPEN"
            latency = f"{result['latency_ms']:.1f} ms"
            port_ok += 1
        elif result["ok"]:
            status = "OPEN"
            latency = "verbunden"
            port_ok += 1
        else:
            status = "FAIL"
            latency = "geschlossen"

        table.append(
            f"{label[:20]:<20} {status:<11} {latency}"
        )

    table.append("")
    table.append(
        f"Hosts                 {host_ok}/{len(host_targets)}"
    )
    table.append(
        f"Ports                 {port_ok}/{min(len(port_targets), 20)}"
    )
    table.append(
        f"Snapshot              {datetime.now().strftime('%d.%m.%Y • %H:%M')}"
    )

    return "\n".join([
        "🏓 Ping",
        "────────────────────────────────",
        "",
        f"<pre>{chr(10).join(table)}</pre>",
    ])


def format_help(snapshot: Snapshot) -> str:
    table = [
        "BEREICH                FUNKTION",
        "Start                  Gesamtübersicht",
        "Status                 System- und Gaststatus",
        "Host                   Hostinformationen",
        "Alerts                 Aktive Warnungen",
        "Storage                Storage-Auslastung",
        "Netzwerk               Netzwerkstatus",
        "Updates                Verfügbare Updates",
        "QEMU                   Virtuelle Maschinen",
        "LXC                    Container",
        "SMART                  Laufwerkszustand",
        "Logs                   Guardian-Logs",
        "Temperaturen           Hardwaretemperaturen",
        "Backup                 Backupstatus",
        "Refresh                Snapshot aktualisieren",
        "Ping                   Hosts und Ports live prüfen",
    ]

    return "\n".join([
        "ℹ️ Hilfe",
        "────────────────────────────────",
        "",
        f"<pre>{chr(10).join(table)}</pre>",
    ])

def format_network(snapshot: Snapshot) -> str:
    local_ip = str(
        snapshot.get("lan_ip", snapshot.get("local_ip", "unbekannt"))
    )
    wan_ip = str(snapshot.get("wan_ip", "unbekannt"))
    dns = "OK" if snapshot.get("dns_ok", False) else "FAIL"
    internet = "ONLINE" if snapshot.get("internet_online", False) else "OFFLINE"
    telegram = "OK" if snapshot.get("telegram_online", False) else "FAIL"

    table = [
        "BEREICH                WERT",
        f"Host                   {str(snapshot.get('hostname', 'unbekannt'))[:30]}",
        f"LAN                    {local_ip[:30]}",
        f"WAN                    {wan_ip[:30]}",
        f"DNS                    {dns}",
        f"Internet               {internet}",
        f"Telegram               {telegram}",
    ]

    interfaces = snapshot.get("interfaces", []) or []

    if interfaces:
        table.append("")
        table.append("INTERFACE              STATUS / IP")

        for row in interfaces[:12]:
            text = str(row).replace("\n", " ")
            table.append(text[:62])

    table.append("")
    table.append(
        f"Snapshot               {snapshot.get('last_check', 'unbekannt')}"
    )

    return "\n".join([
        "🌐 Netzwerk",
        "────────────────────────────────",
        "",
        f"<pre>{chr(10).join(table)}</pre>",
    ])


def format_temps(snapshot: Snapshot) -> str:
    cpu_temp = snapshot.get("cpu_temp")
    nvme_temp = snapshot.get("nvme_temp")
    hdd_temp = snapshot.get("hdd_temp")
    sensors = snapshot.get("sensors", [])

    def temp_state(value):
        try:
            value = float(value)
        except Exception:
            return "?", "unbekannt"

        if value >= 85:
            return "HOT", "kritisch"
        if value >= 75:
            return "WARN", "erhöht"
        return "OK", "normal"

    table = [
        "SENSOR                 TEMP       STATUS"
    ]

    values = [
        ("CPU", cpu_temp),
        ("NVMe", nvme_temp),
        ("HDD/SSD", hdd_temp),
    ]

    for name, value in values:
        if value is None:
            table.append(f"{name:<22} {'n/a':<10} unbekannt")
            continue

        icon, state = temp_state(value)
        table.append(
            f"{name:<22} {float(value):>5.1f} C   {icon:<5} {state}"
        )

    for sensor in sensors[:MAX_SENSORS]:
        name = str(sensor.get("name", "Sensor"))[:20]
        value = str(sensor.get("value", "n/a"))
        unit = str(sensor.get("unit", ""))
        table.append(
            f"{name:<22} {value + unit:<10}"
        )

    table.append("")
    table.append(
        f"Snapshot               {snapshot.get('last_check', 'unbekannt')}"
    )

    return "\n".join([
        "🌡 Temperaturen",
        "────────────────────────────────",
        "",
        f"<pre>{chr(10).join(table)}</pre>",
    ])


def format_alerts(snapshot: Snapshot) -> str:
    alerts = snapshot.get("alerts", []) or []

    critical = [
        a for a in alerts
        if isinstance(a, dict)
        and not a.get("recovered")
        and a.get("severity") == "critical"
    ]

    warning = [
        a for a in alerts
        if isinstance(a, dict)
        and not a.get("recovered")
        and a.get("severity") == "warning"
    ]

    recovered = [
        a for a in alerts
        if isinstance(a, dict) and a.get("recovered")
    ]

    def detail(alert):
        title = str(alert.get("title", "")).strip()
        detail_lines = str(
            alert.get("details", "")
        ).strip().splitlines()

        text = detail_lines[0][:40] if detail_lines else ""
        source = str(alert.get("source", "")).strip()[:18]

        if text:
            return f"{title[:36]} — {text}"
        if source:
            return f"{title[:36]} — {source}"
        return title[:55] or "Unbekannter Alert"

    table = [
        "BEREICH                ANZAHL",
        f"Kritisch               {len(critical)}",
        f"Warnungen              {len(warning)}",
        f"Recoveries             {len(recovered)}",
    ]

    if critical:
        table.append("")
        table.append("KRITISCH               DETAIL")
        for alert in critical[:MAX_ALERTS_ACTIVE]:
            table.append(f"!                      {detail(alert)}")

    if warning:
        table.append("")
        table.append("WARNUNGEN              DETAIL")
        for alert in warning[:MAX_ALERTS_ACTIVE]:
            table.append(f"*                      {detail(alert)}")

    if recovered:
        table.append("")
        table.append("RECOVERIES             DETAIL")
        for alert in recovered[:MAX_ALERTS_RECOVERED]:
            table.append(f"+                      {detail(alert)}")

    if not critical and not warning and not recovered:
        table.append("")
        table.append("Status                 Keine aktiven Warnungen")

    table.append("")
    table.append(
        f"Snapshot               {snapshot.get('last_check', 'unbekannt')}"
    )

    return "\n".join([
        "🚨 Alerts",
        "────────────────────────────────",
        "",
        f"<pre>{chr(10).join(table)}</pre>",
    ])


def format_logs():
    table = ["ZEIT / LOG"]

    try:
        all_lines = (
            Path(LOG_FILE)
            .read_text(encoding="utf-8")
            .splitlines()
        )

        ignored_patterns = (
            "Telegram getUpdates status=200",
            "callback profile",
            "Telegram edit übersprungen: message is not modified",
        )

        log_lines = [
            line for line in all_lines
            if not any(pattern in line for pattern in ignored_patterns)
            and not (
                "Telegram editMessageText status=400" in line
                and "message is not modified" in line
            )
        ][-MAX_LOG_LINES:]

        if log_lines:
            for line in log_lines[-8:]:
                entry = str(line).strip()
                if len(entry) > 220:
                    entry = entry[:217] + "..."
                # Logzeilen enthalten z. B. "<urllib3...>" -> HTML-Fehler ohne Escaping
                table.append(_html.escape(entry, quote=False))
        else:
            table.append("Keine relevanten Logs vorhanden.")

    except Exception as e:
        table.append(f"Fehler: {e}")

    return "\n".join([
        "📜 Logs",
        "────────────────────────────────",
        "",
        f"<pre>{chr(10).join(table)}</pre>",
    ])

def format_power(snapshot=None):
    lines = _msg_title("⚡", "Power")
    package = _read_first_existing([
        "/sys/class/powercap/intel-rapl:0/energy_uj",
        "/sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj",
    ])
    power_now = _read_first_existing([
        "/sys/class/powercap/intel-rapl:0/power_uw",
        "/sys/class/powercap/intel-rapl/intel-rapl:0/power_uw",
    ])
    total_power = _read_first_existing([
        "/sys/class/hwmon/hwmon0/power1_average",
        "/sys/class/hwmon/hwmon1/power1_average",
    ])
    rows = [
        _msg_kv("CPU Package Power", f"{(int(power_now)/1000000):.2f} W" if power_now.isdigit() else "nicht verfügbar"),
        _msg_kv("Gesamtverbrauch", f"{(int(total_power)/1000000):.2f} W" if total_power.isdigit() else "nicht verfügbar"),
        _msg_kv("Energie heute", f"{(int(package)/1000000):.2f} J (seit Boot/Reset)" if package.isdigit() else "nicht verfügbar"),
    ]
    _msg_section(lines, "Leistung", rows)
    lines.extend(_msg_footer(snapshot))
    return _clean_join(lines)

def format_services(snapshot=None):
    lines = _msg_title("🌐", "Services")
    services = ["pveproxy", "pvedaemon", "pvestatd", "corosync", "docker", "nginx", "ssh"]
    rows = []
    for svc in services:
        status = _run_cmd(f"systemctl is-active {svc}") or "unknown"
        icon = "🟢" if status == "active" else "🔴"
        label = "running" if status == "active" else "stopped"
        rows.append(f"{icon} {svc}: {label}")
    _msg_section(lines, "Dienste", rows)
    lines.extend(_msg_footer(snapshot))
    return _clean_join(lines)

def format_performance(snapshot=None):
    node = _detect_node(snapshot)
    status = _json_cmd(f"pvesh get /nodes/{node}/status --output-format json") or {}
    lines = _msg_title("📈", "Performance")
    cpu = float(status.get("cpu", 0) or 0) * 100
    mem = status.get("memory", {}) if isinstance(status.get("memory"), dict) else {}
    load = status.get("loadavg", []) if isinstance(status.get("loadavg"), list) else []
    net = _run_cmd("cat /proc/net/dev")
    up = down = 0
    for row in net.splitlines()[2:]:
        if ":" not in row:
            continue
        iface, data = row.split(":", 1)
        iface = iface.strip()
        if iface == "lo":
            continue
        parts = data.split()
        if len(parts) >= 16:
            down += int(parts[0])
            up += int(parts[8])
    top = _run_cmd("ps -eo pid,comm,%cpu --sort=-%cpu | head -n 6")
    rows = [
        _msg_kv("CPU-Auslastung", f"{cpu:.1f} %"),
        _msg_kv("RAM-Auslastung", _fmt_pct(mem.get("used", 0), mem.get("total", 0))),
        _msg_kv("Load Average", ", ".join(str(x).strip() for x in load[:3]) or "unbekannt"),
        _msg_kv("Netz Down", _fmt_bytes(down)),
        _msg_kv("Netz Up", _fmt_bytes(up)),
    ]
    _msg_section(lines, "Übersicht", rows)
    top_rows = []
    for row in top.splitlines()[1:6]:
        top_rows.append(f"• {row.strip()}")
    _msg_section(lines, "Top CPU-Prozesse", top_rows or ["Keine Daten"])
    lines.extend(_msg_footer(snapshot))
    return _clean_join(lines)

def format_storage(snapshot=None):
    node = _detect_node(snapshot)
    lines = _msg_title("💾", "Storage")
    data = _json_cmd(f"pvesh get /nodes/{node}/storage --output-format json") or []

    def short_bytes(num):
        try:
            num = float(num)
        except Exception:
            return "?"
        units = ["B", "K", "M", "G", "T", "P"]
        for unit in units:
            if abs(num) < 1024.0 or unit == units[-1]:
                if unit == "B":
                    return f"{int(num)}{unit}"
                return f"{num:.1f}{unit}"
            num /= 1024.0
        return "?"

    blocks = []
    if isinstance(data, list):
        for item in data:
            name = str(item.get("storage", "unbekannt"))[:12]
            total = item.get("total", 0) or 0
            used = item.get("used", 0) or 0
            avail = item.get("avail", 0) or 0
            pct = _fmt_pct(used, total).replace(" %", "%")
            blocks.append([
                f"{name:<12}",
                f"T {_fmt_bytes(total):>8}",
                f"U {_fmt_bytes(used):>8}",
                f"F {_fmt_bytes(avail):>8}",
                f"P {pct:>8}",
            ])

    table_lines = []
    col_gap = "   "

    for i in range(0, len(blocks), 2):
        left = blocks[i]
        right = blocks[i + 1] if i + 1 < len(blocks) else None

        if right:
            table_lines.append(f"{left[0]:<22}{col_gap}{right[0]:<22}")
            table_lines.append(f"{left[1]:<22}{col_gap}{right[1]:<22}")
            table_lines.append(f"{left[2]:<22}{col_gap}{right[2]:<22}")
            table_lines.append(f"{left[3]:<22}{col_gap}{right[3]:<22}")
            table_lines.append(f"{left[4]:<22}{col_gap}{right[4]:<22}")
            table_lines.append("")
        else:
            table_lines.append(f"{left[0]:<22}")
            table_lines.append(f"{left[1]:<22}")
            table_lines.append(f"{left[2]:<22}")
            table_lines.append(f"{left[3]:<22}")
            table_lines.append(f"{left[4]:<22}")
            table_lines.append("")

    if table_lines and table_lines[-1] == "":
        table_lines.pop()

    datastore_rows = [f"<pre>{chr(10).join(table_lines)}</pre>"] if table_lines else ["Keine Storage-Daten gefunden."]

    zpool = _run_cmd("zpool status -x")
    _msg_section(lines, "Datastores", datastore_rows)
    _msg_section(lines, "ZFS", [zpool or "Kein ZFS-Pool erkannt."])
    lines.extend(_msg_footer(snapshot))
    return _clean_join(lines)

def format_firewall(snapshot=None):
    node = _detect_node(snapshot)
    lines = _msg_title("🛡", "Firewall")
    cluster = _json_cmd("pvesh get /cluster/firewall/options --output-format json") or {}
    host = _json_cmd(f"pvesh get /nodes/{node}/firewall/options --output-format json") or {}
    rules = _json_cmd(f"pvesh get /nodes/{node}/firewall/rules --output-format json") or []
    rows = [
        _msg_kv("Proxmox-Firewall", "aktiv" if str(host.get("enable", 0)) in ("1", "True", "true") else "inaktiv"),
        _msg_kv("Cluster-Firewall", "aktiv" if str(cluster.get("enable", 0)) in ("1", "True", "true") else "inaktiv"),
        _msg_kv("Host-Firewall", "aktiv" if str(host.get("enable", 0)) in ("1", "True", "true") else "inaktiv"),
        _msg_kv("Aktive Regeln", sum(1 for r in rules if str(r.get("enable", 1)) not in ("0", "False", "false")) if isinstance(rules, list) else 0),
    ]
    _msg_section(lines, "Status", rows)
    lines.extend(_msg_footer(snapshot))
    return _clean_join(lines)

def format_tasks(snapshot=None):
    node = _detect_node(snapshot)
    lines = _msg_title("📋", "Tasks")
    running = _list_running_tasks(node)
    failed = _list_failed_tasks(node, limit=5)
    running_rows = [f"• {t.get('upid', 'task')} ({t.get('type', 'n/a')})" for t in running[:5]]
    failed_rows = [f"• {t.get('upid', 'task')} → {t.get('exitstatus', t.get('status', 'error'))}" for t in failed[:5]]
    from monitor import get_backup_status  # späte Bindung, vermeidet Zirkelimport
    backup_lines = get_backup_status(snapshot).splitlines()
    backup_state = backup_lines[2] if len(backup_lines) > 2 else "unbekannt"
    repl = _run_cmd("pvesh get /cluster/replication --output-format json")
    repl_state = "vorhanden" if repl else "nicht vorhanden"
    _msg_section(lines, "Laufende Tasks", running_rows or ["Keine laufenden Tasks."])
    _msg_section(lines, "Fehlgeschlagene Tasks", failed_rows or ["Keine fehlgeschlagenen Tasks."])
    _msg_section(lines, "Zusatz", [f"• Backup-Status: {backup_state}", f"• Replikation: {repl_state}"])
    lines.extend(_msg_footer(snapshot))
    return _clean_join(lines)

def format_uptime(snapshot=None):
    node = _detect_node(snapshot)
    lines = _msg_title("⏱", "Uptime")
    status = _json_cmd(f"pvesh get /nodes/{node}/status --output-format json") or {}
    host_rows = [_msg_kv("Host-Uptime", _fmt_duration(status.get("uptime", 0)))]
    _msg_section(lines, "Host", host_rows)

    qemu_rows = []
    for row in _parse_table_lines(_run_cmd("qm list")):
        parts = row.split()
        if len(parts) >= 3:
            vmid = parts[0]
            name = parts[1]
            st = parts[2]
            uptime = "läuft" if st.lower() == "running" else "stopped"
            qemu_rows.append(f"• VM {vmid} ({name}): {uptime}")

    lxc_rows = []
    for row in _parse_table_lines(_run_cmd("pct list")):
        parts = row.split()
        if len(parts) >= 3:
            ctid = parts[0]
            name = parts[1]
            st = parts[2]
            uptime = "läuft" if st.lower() == "running" else "stopped"
            lxc_rows.append(f"• LXC {ctid} ({name}): {uptime}")

    _msg_section(lines, "QEMU", qemu_rows or ["Keine VMs gefunden."])
    _msg_section(lines, "LXC", lxc_rows or ["Keine Container gefunden."])
    lines.extend(_msg_footer(snapshot))
    return _clean_join(lines)




