#!/usr/bin/env python3
import sys

# monitor.py läuft als __main__. guardian_checks importiert "monitor" –
# ohne diesen Alias würde Python die Datei ein zweites Mal ausführen
# (zweiter Logger-Aufbau, zweites load_dotenv, doppelte Modulzustände).
if __name__ == "__main__":
    sys.modules.setdefault("monitor", sys.modules[__name__])

import re
import json
import html
import logging
from logging.handlers import RotatingFileHandler
import os
import shutil
import socket
import subprocess
import tempfile
import time
import threading
import traceback
import csv

DEBUG_MODE = False
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any
from guardian_checks import build_guardian_bundle
from guardian_alerts import format_professional_alert
from guardian_config import STATE_FILE as GUARDIAN_STATE_FILE
from utils import _run_cmd, _json_cmd, _read_first_existing, _fmt_bytes, _fmt_pct, _fmt_duration, _detect_node, _run_backup_cmd, _parse_table_lines, _parse_vm_ids, atomic_write_json, load_json, save_json, load_offset, save_offset, run_cmd, fmt_gb, format_uptime_seconds, get_load, get_kernel, reboot_required, get_apt_updates, install_apt_updates, get_rootfs, get_storage_local, get_cpu_temp, get_all_temps, get_smart_summary, get_zfs_status, internet_online, telegram_online, dns_ok, get_lan_ip, get_interfaces, ping_target, tcp_port_check, _parse_backup_storages, _extract_guest_from_volid, _count_backups_for_storage, _list_running_tasks, _list_failed_tasks

from notifications import _alert_category_meta, _alert_key, _alert_text, _alert_time
from guardian_runtime import RedactingFilter, UiState, Outbox

import psutil
import requests
from dotenv import load_dotenv

BASE_DIR = Path(os.getenv("MONITOR_BASE_DIR", Path(__file__).resolve().parent))


from telegram import (
    configure as telegram_configure,
    escape_tg,
    safe_telegram_text,
    telegram_api,
    send_telegram,
    edit_telegram,
    answer_callback,
)
LOG_DIR = BASE_DIR / "logs"
STATE_FILE = BASE_DIR / "state.json"
_APT_INSTALL_LOCK = threading.Lock()
OFFSET_FILE = BASE_DIR / "telegram_offset.txt"
LOG_FILE = LOG_DIR / "monitor.log"
SNAPSHOT_CACHE_FILE = BASE_DIR / "snapshot_cache.json"
SNAPSHOT_MAX_AGE = 15 * 60

load_dotenv(BASE_DIR / ".env", override=True)

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()
CHAT_IDS = [x.strip() for x in os.getenv("TELEGRAM_CHAT_IDS", CHAT_ID).split(",") if x.strip()]
HOST_LABEL = os.getenv("HOST_LABEL", "Proxmox Guardian").strip()

CHECK_INTERVAL = 120
POLL_INTERVAL = 0

PROXMOX_HOST = os.getenv("PROXMOX_HOST", "127.0.0.1").strip()
PROXMOX_NODE = os.getenv("PROXMOX_NODE", "pve").strip()
PROXMOX_USER = os.getenv("PROXMOX_USER", "root@pam").strip()
PROXMOX_TOKEN_NAME = os.getenv("PROXMOX_TOKEN_NAME", "").strip()
PROXMOX_TOKEN_VALUE = os.getenv("PROXMOX_TOKEN_VALUE", "").strip()

WAN_CACHE_SECONDS = 21600
MAX_WORKERS = 8

MAX_STORAGE_ENTRIES = 12
MAX_ALERTS_ACTIVE = 15
MAX_ALERTS_RECOVERED = 10
MAX_SENSORS = 10
MAX_LOG_LINES = 15
TELEGRAM_MSG_LIMIT = 4000

telegram_configure(BOT_TOKEN, CHAT_ID, TELEGRAM_MSG_LIMIT, chat_ids=CHAT_IDS)

WARN_CPU = 85
CRIT_CPU = 95
WARN_RAM = 85
CRIT_RAM = 95
WARN_ROOTFS = 85
CRIT_ROOTFS = 95
WARN_STORAGE = 85
CRIT_STORAGE = 95
WARN_TEMP = 75
CRIT_TEMP = 85

CPU_SUSTAIN_SECONDS = 300
RAM_SUSTAIN_SECONDS = 300
DNS_DOWN_MIN_SECONDS = 60
DNS_RECOVER_MIN_SECONDS = 60
FLAP_WINDOW_SECONDS = 1800
FLAP_THRESHOLD = 3

ALERT_REMINDER_SECONDS = 21600
WARN_REMINDER_SECONDS = 43200
SNAPSHOT_STALE_SECONDS = 900
API_STALE_SECONDS = 300
TASK_REPEAT_THRESHOLD = 3

LOG_DIR.mkdir(parents=True, exist_ok=True)

logger = logging.getLogger("proxmox_guardian")
logger.setLevel(logging.INFO)
logger.handlers.clear()
# Keine Weitergabe an den Root-Logger -> keine doppelten Zeilen im Journal
logger.propagate = False

formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
_redact_filter = RedactingFilter()
file_handler = RotatingFileHandler(LOG_FILE, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
file_handler.setFormatter(formatter)
file_handler.addFilter(_redact_filter)
logger.addHandler(file_handler)

console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
console_handler.addFilter(_redact_filter)
logger.addHandler(console_handler)

# Telegram-Modul und Check-Module loggen über Kind-Logger
logging.getLogger("proxmox_guardian.telegram").setLevel(logging.INFO)

UI_STATE = UiState(BASE_DIR / "ui_state.json")
OUTBOX = Outbox(BASE_DIR / "outbox.json")
SNAPSHOT_LOCK = threading.Lock()

# Schlüssel, die der Alert-Engine gehören und bei einem manuellen
# Refresh nicht verloren gehen dürfen.
ENGINE_KEYS = (
    "guardian_alert_engine", "guardian_meta", "guardian_alerts_active",
    "guardian_alerts_recent", "alerts", "alert_count", "health", "health_score",
    "health_counts", "guardian_summary", "guardian_initialized",
)

if not CHAT_IDS:
    logger.error(
        "TELEGRAM_CHAT_IDS/TELEGRAM_CHAT_ID leer – Bot nimmt KEINE Befehle an "
        "(fail-closed). Bitte .env prüfen."
    )

last_check_ts = 0
last_poll_ts = 0

Snapshot = dict[str, Any]


def log(msg):
    logger.info(msg)



def build_menu(view="home"):
    rows = [
        [
            {"text": "🏠 Start", "callback_data": "home"},
            {"text": "📊 Status", "callback_data": "status"},
            {"text": "🖥 Host", "callback_data": "host"},
        ],
        [
            {"text": "🚨 Alerts", "callback_data": "alerts"},
            {"text": "💾 Storage", "callback_data": "storage"},
            {"text": "🌐 Netz", "callback_data": "network"},
        ],
        [
            {"text": "📦 Updates", "callback_data": "updates"},
            {"text": "📊 QEMU", "callback_data": "qemu"},
            {"text": "📦 LXC", "callback_data": "lxc"},
        ],
        [
            {"text": "💿 SMART", "callback_data": "smart"},
            {"text": "📜 Logs", "callback_data": "logs"},
            {"text": "🌡 Temps", "callback_data": "temps"},
        ],
        [
            {"text": "💾 Backup", "callback_data": "backup"},
            {"text": "🔄 Refresh", "callback_data": f"refresh:{view}"},
            {"text": "🏓 Ping", "callback_data": "ping"},
        ],
    ]

    invisible = "\u2800"

    def pad_label(label, target_len):
        missing = max(0, target_len - len(label))
        left = missing // 2
        right = missing - left
        return f"{invisible * left}{label}{invisible * right}"

    max_len = max(len(btn["text"]) for row in rows for btn in row)

    padded_rows = []
    for row in rows:
        padded_row = []
        for btn in row:
            item = dict(btn)
            item["text"] = pad_label(item["text"], max_len)
            padded_row.append(item)
        padded_rows.append(padded_row)

    return {"inline_keyboard": padded_rows}



def build_network_menu():
    return {
        "inline_keyboard": [
            [
                {
                    "text": "📡 WAN-Monitor",
                    "callback_data": "wan_monitor",
                },
                {
                    "text": "📜 WAN-Logs",
                    "callback_data": "wan_logs",
                },
            ],
            [
                {
                    "text": "🔄 Refresh",
                    "callback_data": "refresh:network",
                },
            ],
            [
                {
                    "text": "🏠 Start",
                    "callback_data": "home",
                },
            ],
        ]
    }


def build_wan_monitor_menu():
    return {
        "inline_keyboard": [
            [
                {
                    "text": "📜 WAN-Logs",
                    "callback_data": "wan_logs",
                },
                {
                    "text": "🔄 Refresh",
                    "callback_data": "refresh:wan_monitor",
                },
            ],
            [
                {
                    "text": "⬅️ Netz",
                    "callback_data": "network",
                },
                {
                    "text": "🏠 Start",
                    "callback_data": "home",
                },
            ],
        ]
    }


def build_wan_logs_menu():
    return {
        "inline_keyboard": [
            [
                {
                    "text": "📊 Statistik",
                    "callback_data": "wan_stats",
                },
                {
                    "text": "📄 Provider-Bericht",
                    "callback_data": "wan_report",
                },
            ],
            [
                {
                    "text": "📶 Geräte-Verbindungen",
                    "callback_data": "device_connections",
                },
            ],
            [
                {
                    "text": "📨 Bericht lfd. Monat",
                    "callback_data": "wan_monthly:current",
                },
                {
                    "text": "📨 Bericht Vormonat",
                    "callback_data": "wan_monthly:previous",
                },
            ],
            [
                {
                    "text": "🔄 Refresh",
                    "callback_data": "refresh:wan_logs",
                },
                {
                    "text": "⬅️ WAN",
                    "callback_data": "wan_monitor",
                },
            ],
            [
                {
                    "text": "⬅️ Netz",
                    "callback_data": "network",
                },
                {
                    "text": "🏠 Start",
                    "callback_data": "home",
                },
            ],
        ]
    }


def _msg_title(icon: str, title: str) -> list[str]:
    return [f"{icon} {title}", ""]

def _msg_section(lines: list[str], title: str, rows: list[str]) -> None:
    rows = [str(r) for r in rows if str(r).strip()]
    if not rows:
        return
    if lines and lines[-1] != "":
        lines.append("")
    lines.append(title)
    lines.extend(rows)

def _msg_kv(label: str, value, prefix: str = "•") -> str:
    return f"{prefix} {label}: {value}"

def _msg_footer(snapshot=None, label: str = "Letzte Prüfung") -> list[str]:
    ts = datetime.now().strftime("%d.%m.%Y • %H:%M")
    if isinstance(snapshot, dict):
        ts = snapshot.get("last_check", ts) or ts
    return ["", f"🕒 {label}: {ts}"]

def _clean_join(lines: list[str]) -> str:
    out = []
    last_blank = False
    for line in lines:
        cur = str(line)
        if cur == "":
            if not last_blank:
                out.append(cur)
            last_blank = True
        else:
            out.append(cur)
            last_blank = False
    return "\n".join(out).strip()


def get_wan_ip_cached(previous_snapshot, lan_ip):
    now = int(time.time())
    old_cache = {}
    if isinstance(previous_snapshot, dict):
        old_cache = previous_snapshot.get("wan_cache", {}) or {}
    old_wan = old_cache.get("wan_ip", "unbekannt")
    old_ts = int(old_cache.get("timestamp", 0) or 0)
    old_lan = old_cache.get("lan_ip", "")

    if old_wan and old_wan != "unbekannt" and old_lan == lan_ip and (now - old_ts) < WAN_CACHE_SECONDS:
        return {"wan_ip": old_wan, "timestamp": old_ts, "lan_ip": lan_ip, "cached": True}

    try:
        wan = requests.get("https://api.ipify.org", timeout=6).text.strip()
        return {"wan_ip": wan or old_wan or "unbekannt", "timestamp": now, "lan_ip": lan_ip, "cached": False}
    except Exception:
        return {"wan_ip": old_wan or "unbekannt", "timestamp": old_ts or now, "lan_ip": lan_ip, "cached": True}






def get_uptime():
    try:
        seconds = int(time.time() - psutil.boot_time())
        hours = seconds // 3600
        if hours < 24:
            return f"{hours} Std"
        return f"{hours // 24} Tage"
    except Exception:
        return "unbekannt"









def proxmox_api(path):
    if not (PROXMOX_TOKEN_NAME and PROXMOX_TOKEN_VALUE):
        return []
    url = f"https://{PROXMOX_HOST}:8006/api2/json{path}"
    headers = {"Authorization": f"PVEAPIToken={PROXMOX_USER}!{PROXMOX_TOKEN_NAME}={PROXMOX_TOKEN_VALUE}"}
    try:
        r = requests.get(url, headers=headers, timeout=5, verify=False)
        r.raise_for_status()
        return r.json().get("data", [])
    except Exception as e:
        log(f"Proxmox API Fehler {path}: {e}")
        return []


def proxmox_api_dict(path):
    data = proxmox_api(path)
    return data if isinstance(data, dict) else {}


def get_cluster_resources():
    data = proxmox_api("/cluster/resources")
    return data if isinstance(data, list) else []




def overall_status(snapshot):
    alerts = snapshot.get("alerts", [])
    active = [a for a in alerts if not str(a).startswith("✅")]

    if any("🚨" in str(a) for a in active):
        return "🚨 Kritische Probleme erkannt"
    if any("⚠️" in str(a) for a in active):
        return "⚠️ Warnungen vorhanden"
    return "✅ System wirkt stabil"


# VMs, deren Guest Agent nicht antwortet, werden für GUEST_AGENT_BACKOFF
# Sekunden übersprungen (Proxmox-Wert wird verwendet). Vorher blockierte
# z. B. VM 104 jeden Zyklus 8 s und erzeugte "qga command failed" im Journal.
GUEST_AGENT_BACKOFF = 600
_guest_agent_fail_until: dict[str, float] = {}


def get_guest_memory(vmid):
    """Liest die tatsächliche RAM-Nutzung einer QEMU-VM über den Guest Agent."""
    key = str(vmid)
    if _guest_agent_fail_until.get(key, 0) > time.time():
        return None
    result_value = _get_guest_memory_uncached(vmid)
    if result_value is None:
        _guest_agent_fail_until[key] = time.time() + GUEST_AGENT_BACKOFF
    else:
        _guest_agent_fail_until.pop(key, None)
    return result_value


def _get_guest_memory_uncached(vmid):
    try:
        result = subprocess.run(
            ["qm", "guest", "exec", str(vmid), "--", "cat", "/proc/meminfo"],
            capture_output=True,
            text=True,
            timeout=8,
        )

        if result.returncode != 0:
            return None

        data = json.loads(result.stdout)
        text = data.get("out-data", "")

        values = {}
        for line in text.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            parts = value.strip().split()
            if parts:
                try:
                    values[key] = float(parts[0])
                except ValueError:
                    pass

        total = values.get("MemTotal")
        available = values.get("MemAvailable")

        if not total or available is None:
            return None

        used = max(0.0, total - available)

        # /proc/meminfo liefert kB
        return {
            "mem_used": int(used * 1024),
            "mem_max": int(total * 1024),
            "mem_available": int(available * 1024),
            "mem_source": "guest_agent",
        }

    except Exception as e:
        log(f"Guest RAM Fehler VM {vmid}: {e}")
        return None


def build_snapshot(previous_snapshot=None):
    previous_snapshot = previous_snapshot or {}
    now_human = datetime.now().strftime("%d.%m.%Y • %H:%M")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {
            "cluster_resources": pool.submit(get_cluster_resources),
            "node_status": pool.submit(proxmox_api_dict, f"/nodes/{PROXMOX_NODE}/status"),
            "tasks": pool.submit(proxmox_api, f"/nodes/{PROXMOX_NODE}/tasks?limit=10"),
            "backup_jobs": pool.submit(proxmox_api, "/cluster/backup"),
            "backup_tasks": pool.submit(
                proxmox_api,
                f"/nodes/{PROXMOX_NODE}/tasks?typefilter=vzdump&limit=20"
            ),
            "version": pool.submit(proxmox_api_dict, "/version"),
            "storage_local": pool.submit(get_storage_local),
            "smart": pool.submit(get_smart_summary),
            "zfs": pool.submit(get_zfs_status),
            "temps": pool.submit(get_all_temps),
            "cpu_temp": pool.submit(get_cpu_temp),
            "lan_ip": pool.submit(get_lan_ip),
            "internet": pool.submit(internet_online),
            "telegram": pool.submit(telegram_online),
            "dns": pool.submit(dns_ok),
            "kernel": pool.submit(get_kernel),
            "rootfs": pool.submit(get_rootfs),
            "uptime": pool.submit(get_uptime),
            "load": pool.submit(get_load),
            "reboot": pool.submit(reboot_required),
            "apt_updates": pool.submit(get_apt_updates),
        }

        results = {}
        for key, future in futures.items():
            try:
                results[key] = future.result(timeout=30)
            except Exception as e:
                log(f"Collector Fehler {key}: {e}")
                results[key] = {} if key in ("node_status", "version") else []

    resources = results.get("cluster_resources", []) or []
    node_resources = [r for r in resources if r.get("type") == "node"]
    qemu_resources = [r for r in resources if r.get("type") == "qemu" and r.get("node") == PROXMOX_NODE]
    lxc_resources = [r for r in resources if r.get("type") == "lxc" and r.get("node") == PROXMOX_NODE]
    storage_resources = [r for r in resources if r.get("type") == "storage" and r.get("node") == PROXMOX_NODE]

    storages = []
    if storage_resources:
        for s in storage_resources:
            total = s.get("maxdisk", 0) or 0
            used = s.get("disk", 0) or 0
            avail = max(0, total - used)
            pct = round((used / total) * 100, 1) if total else 0
            storages.append({
                "storage": s.get("storage", s.get("id", "unknown")),
                "type": s.get("plugintype", s.get("content", "unknown")),
                "total": total,
                "used": used,
                "avail": avail,
                "percent": f"{pct}%",
                "status": s.get("status", "unknown"),
            })
    else:
        storages = results.get("storage_local", []) or []

    # Guest-Agent-Abfragen parallel statt nacheinander
    running_ids = [vm.get("vmid") for vm in qemu_resources if str(vm.get("status", "")).lower() == "running"]
    guest_mem_map = {}
    if running_ids:
        with ThreadPoolExecutor(max_workers=min(4, len(running_ids))) as gpool:
            for vmid, mem in zip(running_ids, gpool.map(get_guest_memory, running_ids)):
                guest_mem_map[vmid] = mem

    qemu = []
    for vm in qemu_resources:
        vmid = vm.get("vmid")
        status = vm.get("status", "unknown")

        guest_mem = guest_mem_map.get(vmid)

        qemu.append({
            "vmid": vmid,
            "name": vm.get("name", f"vm-{vmid}"),
            "status": status,
            "cpu": round((vm.get("cpu", 0) or 0) * 100, 1),
            "mem_used": (
                guest_mem["mem_used"]
                if guest_mem
                else (vm.get("mem", 0) or 0)
            ),
            "mem_max": (
                guest_mem["mem_max"]
                if guest_mem
                else (vm.get("maxmem", 0) or 0)
            ),
            "mem_available": (
                guest_mem["mem_available"]
                if guest_mem
                else None
            ),
            "mem_source": (
                guest_mem["mem_source"]
                if guest_mem
                else "proxmox"
            ),
            "uptime": vm.get("uptime", 0) or 0,
            "node": vm.get("node", PROXMOX_NODE),
        })

    lxc = []
    for ct in lxc_resources:
        lxc.append({
            "vmid": ct.get("vmid"),
            "name": ct.get("name", f"ct-{ct.get('vmid')}"),
            "status": ct.get("status", "unknown"),
            "cpu": round((ct.get("cpu", 0) or 0) * 100, 1),
            "mem_used": ct.get("mem", 0) or 0,
            "mem_max": ct.get("maxmem", 0) or 0,
            "uptime": ct.get("uptime", 0) or 0,
            "node": ct.get("node", PROXMOX_NODE),
        })

    # Host-Ressourcen direkt aus der Proxmox-API verwenden.
    # Keine eigene psutil-Messung, damit die Werte der Proxmox-GUI entsprechen.
    node_status = results.get("node_status") or {}

    raw_cpu = node_status.get("cpu", 0) or 0
    cpu = round(float(raw_cpu) * 100, 1)

    memory = node_status.get("memory") or {}
    mem_total = float(memory.get("total", 0) or 0)
    mem_used = float(memory.get("used", 0) or 0)
    ram = round((mem_used / mem_total) * 100, 1) if mem_total > 0 else 0.0

    rootfs = results.get("rootfs") or {"total_gb": 0, "used_gb": 0, "free_gb": 0, "percent": 0}
    # Proxmox liefert Load Average und IO-Wait bereits direkt.
    # Diese Werte werden nicht mit eigenen Formeln nachgebildet.
    node_status = results.get("node_status") or {}

    api_load = node_status.get("loadavg") or []
    if isinstance(api_load, (list, tuple)) and len(api_load) >= 3:
        load1 = float(api_load[0])
        load5 = float(api_load[1])
        load15 = float(api_load[2])
    else:
        load1 = load5 = load15 = 0.0

    io_wait = float(node_status.get("wait", 0) or 0) * 100.0

    swap = node_status.get("swap") or {}
    swap_total = float(swap.get("total", 0) or 0)
    swap_used = float(swap.get("used", 0) or 0)
    swap_percent = (
        (swap_used / swap_total) * 100.0
        if swap_total > 0 else 0.0
    )

    lan_ip = results.get("lan_ip") or "unbekannt"
    wan_cache = get_wan_ip_cached(previous_snapshot, lan_ip)

    tasks_raw = results.get("tasks", []) or []
    tasks = []
    for t in tasks_raw[:20]:
        tasks.append({
            "upid": t.get("upid", ""),
            "type": t.get("type", ""),
            "status": t.get("status", ""),
            "user": t.get("user", ""),
            "starttime": t.get("starttime", 0),
            "id": t.get("id", ""),
        })

    failed_tasks = [t for t in tasks if str(t.get("status", "")).lower() in ("error", "failed")]
    running_tasks = [t for t in tasks if not t.get("status")]

    penalties = 0
    alerts = []

    if cpu >= 90:
        penalties += 20
    elif cpu >= 75:
        penalties += 10

    if ram >= 90:
        penalties += 20
    elif ram >= 75:
        penalties += 10

    if rootfs["percent"] >= 95:
        penalties += 20
    elif rootfs["percent"] >= 85:
        penalties += 10

    if not results.get("internet", False):
        penalties += 25
    if not results.get("telegram", False):
        penalties += 10
    if not results.get("dns", False):
        penalties += 10

    for s in storages:
        try:
            pct = float(str(s.get("percent", "0")).replace("%", ""))
            if pct >= 90:
                pass
        except Exception:
            pass

    zfs = results.get("zfs") or "Kein ZFS oder nicht verfügbar"

    smart = results.get("smart", []) or []
    for d in smart:
        health = d.get("health", "").upper()
        if health and "PASSED" not in health and "OK" not in health:
            pass

    health = max(0, 100 - penalties)
    health_color = "🟢" if health >= 90 else "🟡" if health >= 70 else "🔴"

    snapshot = {
        "host": HOST_LABEL,
        "node": PROXMOX_NODE,
        "health": health,
        "health_color": health_color,
        "alerts": [],
        "load1": round(load1, 2),
        "load5": round(load5, 2),
        "load15": round(load15, 2),
        "io_wait": round(io_wait, 2),
        "swap_used": swap_used,
        "swap_total": swap_total,
        "swap_percent": round(swap_percent, 2),
        "alert_count": 0,
        "qemu": qemu,
        "lxc": lxc,
        "storages": storages,
        "tasks": tasks,
        "backup_jobs": results.get("backup_jobs", []) or [],
        "backup_tasks": results.get("backup_tasks", []) or [],
        "failed_tasks": failed_tasks,
        "running_tasks": running_tasks,
        "internet_online": bool(results.get("internet", False)),
        "telegram_online": bool(results.get("telegram", False)),
        "dns_ok": bool(results.get("dns", False)),
        "rootfs": rootfs,
        "cpu": cpu,
        "ram": ram,
        "cpu_temp": results.get("cpu_temp"),
        "temps": results.get("temps", []) or [],
        "hostname": socket.gethostname(),
        "local_ip": lan_ip,
        "wan_ip": wan_cache.get("wan_ip", "unbekannt"),
        "wan_cache": wan_cache,
        "uptime": results.get("uptime") or "unbekannt",
        "kernel": results.get("kernel") or "unbekannt",
        "reboot_required": bool(results.get("reboot", False)),
        "apt_updates": results.get("apt_updates", {}) or {},
        "smart": smart,
        "zfs_status": zfs,
        "node_status": results.get("node_status", {}) or {},
        "version": results.get("version", {}) or {},
        "node_resources": node_resources,
        "last_check": now_human,
        "snapshot_ts": int(time.time()),
        "snapshot_mode": "background-only",
    }
    snapshot["backup_status"] = get_backup_status(snapshot)
    snapshot["storage_view"] = format_storage(snapshot)
    return snapshot



def save_json_atomic(path, data):
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)

def save_snapshot_cache(snapshot):
    if not isinstance(snapshot, dict):
        return
    snap = dict(snapshot)
    now = int(time.time())
    snap["_cache"] = {
        "generated_at": now,
        "stale_after": now + SNAPSHOT_MAX_AGE,
    }
    save_json_atomic(SNAPSHOT_CACHE_FILE, snap)

def load_snapshot_cache():
    data = load_json(SNAPSHOT_CACHE_FILE, {})
    return data if isinstance(data, dict) else {}

def snapshot_cache_is_stale(snapshot):
    cache = snapshot.get("_cache", {}) if isinstance(snapshot, dict) else {}
    generated_at = int(cache.get("generated_at", 0) or 0)
    if not generated_at:
        return True
    return (time.time() - generated_at) > SNAPSHOT_MAX_AGE

def get_cached_snapshot():
    snap = load_snapshot_cache()
    if isinstance(snap, dict) and snap:
        return snap
    state = load_json(STATE_FILE, {})
    return state if isinstance(state, dict) else {}



from views import (
    format_home,
    format_host,
    format_status,
    format_guests,
    format_qemu,
    format_lxc,
    format_updates,
    format_disk,
    format_smart,
    format_ping,
    format_help,
    format_network,
    format_temps,
    format_alerts,
    format_logs,
    format_power,
    format_services,
    format_performance,
    format_storage,
    format_firewall,
    format_tasks,
    format_uptime,
)

def format_storage_view(snapshot):
    if not isinstance(snapshot, dict):
        return "💾 Storage\n\nKeine Daten verfügbar."
    return str(snapshot.get("storage_view") or "💾 Storage\n\nKeine Daten verfügbar.")

def format_backup_view(snapshot):
    if not isinstance(snapshot, dict):
        return "📦 Backup\n\n<pre>Keine Daten verfügbar.</pre>"

    text = str(snapshot.get("backup_status") or "BACKUP\nKeine Daten verfügbar.")
    stripped = text.lstrip()
    if stripped.startswith("<pre>") or stripped.startswith("<b>") or stripped.startswith("<code>"):
        return text

    lines = text.splitlines()
    if not lines:
        return "📦 Backup\n\n<pre>Keine Daten verfügbar.</pre>"

    title = "📦 Backup"
    status = ""
    pruefung = ""
    letztes = ""
    body = []

    for line in lines[1:]:
        s = line.strip()
        if s.startswith("Status"):
            status = " ".join(s.split()[1:])
        elif s.startswith("Prüfung"):
            pruefung = " ".join(s.split()[1:])
        elif s.startswith("Letztes"):
            letztes = " ".join(s.split()[1:])
        else:
            body.append(line)

    top = [title]
    if status:
        top.append(f"Status: {status}")
    if pruefung:
        top.append(f"Prüfung: {pruefung}")
    if letztes:
        top.append(f"Letztes: {letztes}")

    pre = "\n".join(body).strip() or "Keine Details verfügbar."
    return "\n".join([top[0], "────────────────────────────────", *top[1:]]) + "\n\n<pre>" + pre + "</pre>"

def build_updates_menu(snapshot):
    menu = build_menu("updates")

    apt = snapshot.get("apt_updates", {}) or {}
    available = int(apt.get("available", 0) or 0)

    if available > 0:
        menu["inline_keyboard"].insert(
            0,
            [
                {
                    "text": "⬇️ Updates installieren",
                    "callback_data": "updates:install",
                }
            ],
        )

    return menu




# WAN-, Geräte- und Provider-Ansichten: siehe guardian_wan.py
# (alter Leser verwarf alle V2-Ereignisse wegen 13 statt 11 Spalten)
from guardian_wan import (  # noqa: E402
    format_wan_monitor,
    format_wan_logs,
    format_wan_stats,
    format_device_report,
    format_wan_report,
)


def render_view(view):
    snapshot = get_cached_snapshot()
    mapping = {
        "home": format_home,
        "host": format_host,
        "status": format_status,
        "updates": format_updates,
        "storage": format_storage_view,
        "qemu": format_qemu,
        "lxc": format_lxc,
        "network": format_network,
        "wan_monitor": format_wan_monitor,
        "temps": format_temps,
        "smart": format_smart,
        "alerts": format_alerts,
        "ping": format_ping,
        "backup": format_backup_view,
        "help": format_help,
    }
    if view == "network":
        return format_network(snapshot), build_network_menu()

    if view == "wan_monitor":
        return format_wan_monitor(snapshot), build_wan_monitor_menu()

    if view == "wan_logs":
        return format_wan_logs(snapshot), build_wan_logs_menu()

    if view == "wan_stats":
        return format_wan_stats(snapshot), build_wan_logs_menu()

    if view == "wan_report":
        return format_wan_report(snapshot), build_wan_logs_menu()

    if view == "device_connections":
        return format_device_report(snapshot), build_wan_logs_menu()

    if view == "logs":
        return format_logs(), build_menu("logs")
    fn = mapping.get(view, format_home)
    menu = build_updates_menu(snapshot) if view == "updates" else build_menu(view)
    return fn(snapshot), menu

def _state_bucket(old):
    if not isinstance(old, dict):
        old = {}
    return old.get("_meta", {}) if isinstance(old.get("_meta", {}), dict) else {}

def _ensure_meta(old):
    meta = _state_bucket(old).copy()
    meta.setdefault("cpu_high_since", None)
    meta.setdefault("ram_high_since", None)
    meta.setdefault("vm_events", {})
    meta.setdefault("ct_events", {})
    meta.setdefault("task_fail_counts", {})
    meta.setdefault("storage_history", {})
    meta.setdefault("active_alerts", {})
    meta.setdefault("last_alert_sent", {})
    meta.setdefault("api_fail_since", None)
    meta.setdefault("host_fail_since", None)
    meta.setdefault("smart_bad", {})
    meta.setdefault("zfs_bad_since", None)
    meta.setdefault("backup_fail_counts", {})
    meta.setdefault("raid_bad_since", None)
    meta.setdefault("storage_warn_since", {})
    meta.setdefault("guest_down_since", {})
    meta.setdefault("guest_reboot_seen", {})
    meta.setdefault("guest_grace_until", {})
    meta.setdefault("guest_alert_sent", {})
    meta.setdefault("raid_last_text", "")
    meta.setdefault("zfs_last_text", "")
    meta.setdefault("smart_last_bad", {})
    meta.setdefault("health_states", {})
    return meta

def _entity_map(items):
    out = {}
    for x in items:
        vmid = str(x.get("vmid"))
        if vmid:
            out[vmid] = x
    return out

def _append_event(meta_dict, key, ts, status):
    arr = meta_dict.get(key, [])
    arr.append({"ts": ts, "status": status})
    cutoff = ts - FLAP_WINDOW_SECONDS
    arr = [x for x in arr if int(x.get("ts", 0)) >= cutoff]
    meta_dict[key] = arr
    return arr

def _count_status_changes(events):
    changes = 0
    prev = None
    for ev in events:
        cur = ev.get("status")
        if prev is not None and cur != prev:
            changes += 1
        prev = cur
    return changes

def _top_cpu_consumers(snapshot, limit=3):
    items = []
    for vm in snapshot.get("qemu", []):
        items.append(("VM", vm.get("name", f"VM {vm.get('vmid')}"), float(vm.get("cpu", 0) or 0)))
    for ct in snapshot.get("lxc", []):
        items.append(("LXC", ct.get("name", f"LXC {ct.get('vmid')}"), float(ct.get("cpu", 0) or 0)))
    items.sort(key=lambda x: x[2], reverse=True)
    return [x for x in items if x[2] > 0][:limit]

def _top_ram_consumers(snapshot, limit=3):
    items = []
    for vm in snapshot.get("qemu", []):
        maxmem = float(vm.get("mem_max", 0) or 0)
        mem = float(vm.get("mem_used", 0) or 0)
        pct = round((mem / maxmem) * 100, 1) if maxmem else 0.0
        items.append(("VM", vm.get("name", f"VM {vm.get('vmid')}"), pct))
    for ct in snapshot.get("lxc", []):
        maxmem = float(ct.get("mem_max", 0) or 0)
        mem = float(ct.get("mem_used", 0) or 0)
        pct = round((mem / maxmem) * 100, 1) if maxmem else 0.0
        items.append(("LXC", ct.get("name", f"LXC {ct.get('vmid')}"), pct))
    items.sort(key=lambda x: x[2], reverse=True)
    return [x for x in items if x[2] > 0][:limit]





def handle_message_command(text, chat_id, message_id=None):
    cmd = (text or "").strip().lower()
    mapping = {
        "/start": "home",
        "/home": "home",
        "/host": "host",
        "/status": "status",
        "/storage": "storage",
        "/qemu": "qemu",
        "/lxc": "lxc",
        "/network": "network",
        "/temps": "temps",
        "/alerts": "alerts",
        "/logs": "logs",
        "/help": "help",
        "/updates": "updates",
        "/ping": "ping",
    }
    view = mapping.get(cmd)
    if view:
        body, menu = render_view(view)

        # Menü-Zustand getrennt pro Chat: Account A und B beeinflussen sich nicht.
        old_message_id = UI_STATE.get_menu(chat_id)
        if old_message_id:
            telegram_api("deleteMessage", {"chat_id": chat_id, "message_id": old_message_id})

        resp = send_telegram(body, chat_id=chat_id, reply_markup=menu)
        if isinstance(resp, dict) and resp.get("ok") and resp.get("result"):
            new_id = resp["result"].get("message_id")
            UI_STATE.set_menu(chat_id, new_id, view)
            UI_STATE.remember_render(chat_id, new_id, body, view)

        if message_id:
            telegram_api("deleteMessage", {"chat_id": chat_id, "message_id": message_id})
        return

    if message_id:
        telegram_api("deleteMessage", {"chat_id": chat_id, "message_id": message_id})


def _update_install_worker(chat_id, message_id):
    """Führt eine bestätigte APT-Installation im Hintergrund aus."""
    try:
        result = install_apt_updates()

        if result.get("success"):
            output = str(result.get("output", "") or "Keine Ausgabe.")
            reboot_needed = reboot_required()

            if reboot_needed:
                body = (
                    "📦 Updates\n\n"
                    "✅ Installation erfolgreich abgeschlossen.\n\n"
                    "<pre>" + escape_tg(output[-3000:]) + "</pre>\n\n"
                    "⚠️ Ein Neustart ist erforderlich."
                )
                menu = {
                    "inline_keyboard": [
                        [
                            {
                                "text": "🔄 Jetzt neu starten",
                                "callback_data": "updates:reboot",
                            }
                        ],
                        [
                            {
                                "text": "⬅️ Später",
                                "callback_data": "updates:reboot_cancel",
                            }
                        ],
                    ]
                }
            else:
                body = (
                    "📦 Updates\n\n"
                    "✅ Installation erfolgreich abgeschlossen.\n\n"
                    "<pre>" + escape_tg(output[-3000:]) + "</pre>\n\n"
                    "ℹ️ Kein Neustart erforderlich."
                )
                snapshot = get_cached_snapshot()
                menu = build_updates_menu(snapshot)

        else:
            stage = str(result.get("stage", "unbekannt"))
            output = str(result.get("output", "") or "Keine Ausgabe.")
            body = (
                "📦 Updates\n\n"
                "❌ Installation fehlgeschlagen.\n\n"
                f"Phase: {stage}\n\n"
                f"<pre>{escape_tg(output[-3500:])}</pre>"
            )
            snapshot = get_cached_snapshot()
            menu = build_updates_menu(snapshot)

        if chat_id and message_id:
            edit_telegram(
                chat_id,
                message_id,
                body,
                reply_markup=menu,
            )

        notify_other_admins(
            chat_id,
            f"ℹ️ {escape_tg(HOST_LABEL)}: Update-Installation beendet – "
            + ("erfolgreich." if result.get("success") else "fehlgeschlagen (Details beim auslösenden Account)."),
        )

    except Exception as exc:
        log(f"APT update worker error: {exc}")

        if chat_id and message_id:
            edit_telegram(
                chat_id,
                message_id,
                "📦 Updates\n\n"
                "❌ Unerwarteter Fehler bei der Installation.\n\n"
                f"<pre>{escape_tg(str(exc)[-3500:])}</pre>",
                reply_markup=build_menu("updates"),
            )

    finally:
        _APT_INSTALL_LOCK.release()



def _refresh_view_worker(view, chat_id, message_id):
    """Holt einen frischen Snapshot im Hintergrund und aktualisiert die bestehende Nachricht."""
    try:
        old_snapshot = get_cached_snapshot()
        fresh_snapshot = build_snapshot(old_snapshot)

        # Zustand der Alert-Engine aus dem aktuellen Cache übernehmen.
        # Vorher wurde er hier verworfen -> doppelte Alarme, fehlende Recoveries.
        with SNAPSHOT_LOCK:
            current = load_snapshot_cache()
            for key in ENGINE_KEYS:
                if key in current:
                    fresh_snapshot[key] = current[key]
            save_snapshot_cache(fresh_snapshot)

        body, menu = render_view(view)

        if chat_id and message_id:
            resp = edit_telegram(chat_id, message_id, body, reply_markup=menu)
            if isinstance(resp, dict) and resp.get("ok"):
                UI_STATE.remember_render(chat_id, message_id, body, view)

        log(f"Refresh worker erfolgreich: view={view}")
    except Exception as e:
        log(f"Refresh worker Fehler: {e}")


MONTHLY_REPORT_SCRIPT = "/usr/local/sbin/proxmox-provider-monthly-report.py"


def _monthly_report_worker(chat_id, which):
    """Erzeugt das Störungsprotokoll und schickt es als Datei an den anfragenden Chat."""
    args = [MONTHLY_REPORT_SCRIPT, "--chat", str(int(chat_id))]
    if which == "current":
        args.append("--current")
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            log(f"Monatsbericht Fehler (rc={result.returncode}): {result.stderr.strip()[:300]}")
            send_telegram("⚠️ Monatsbericht konnte nicht erstellt werden. Details im Guardian-Log.", chat_id=chat_id)
    except Exception as exc:
        log(f"Monatsbericht Fehler: {exc}")
        send_telegram("⚠️ Monatsbericht konnte nicht erstellt werden.", chat_id=chat_id)


def _reboot_worker():
    """Führt den kontrollierten Neustart des Proxmox-Hosts aus."""
    try:
        log("System-Reboot wird ausgeführt")
        subprocess.Popen(
            ["/usr/bin/systemctl", "reboot"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception as e:
        log(f"System-Reboot Fehler: {e}")


def _actor_name(callback):
    user = (callback or {}).get("from", {}) or {}
    name = str(user.get("first_name") or user.get("username") or user.get("id") or "unbekannt")
    return escape_tg(name[:40])


def notify_other_admins(origin_chat_id, text):
    """Informiert die jeweils anderen berechtigten Accounts über kritische Aktionen
    (Update-Installation, Neustart), damit beide Admins denselben Kenntnisstand haben."""
    for recipient in CHAT_IDS:
        if str(recipient) != str(origin_chat_id):
            send_telegram(text, chat_id=recipient)


def handle_callback(callback):
    callback_t0 = time.perf_counter()
    callback_id = callback.get("id")
    data = str(callback.get("data") or "home")[:64]
    msg = callback.get("message", {})
    chat_id = msg.get("chat", {}).get("id")
    message_id = msg.get("message_id")

    # Updates: Installation erst nach ausdrücklicher Bestätigung.
    if str(data).strip() == "updates:install":
        snapshot = get_cached_snapshot()
        apt = snapshot.get("apt_updates", {}) or {}
        available = int(apt.get("available", 0) or 0)
        security = int(apt.get("security", 0) or 0)

        if available <= 0:
            if callback_id:
                answer_callback(callback_id, "Keine Updates verfügbar")
            return

        confirm_body = (
            "📦 Updates installieren\n"
            "\n"
            "<pre>"
            "Verfügbare Updates: " + str(available) + "\n"
            "Security-Updates:    " + str(security) + "\n"
            "\n"
            "Der Server wird NICHT automatisch neu gestartet."
            "</pre>"
        )

        confirm_menu = {
            "inline_keyboard": [
                [
                    {
                        "text": "✅ Ja, installieren",
                        "callback_data": "updates:confirm",
                    },
                    {
                        "text": "❌ Abbrechen",
                        "callback_data": "updates:cancel",
                    },
                ]
            ]
        }

        if callback_id:
            answer_callback(callback_id, "Bestätigung erforderlich")

        if chat_id and message_id:
            edit_telegram(
                chat_id,
                message_id,
                confirm_body,
                reply_markup=confirm_menu,
            )
        return

    if str(data).strip() == "updates:cancel":
        if callback_id:
            answer_callback(callback_id, "Abgebrochen")

        body, menu = render_view("updates")

        if chat_id and message_id:
            edit_telegram(chat_id, message_id, body, reply_markup=menu)
        return

    if str(data).strip() == "updates:reboot_cancel":
        if callback_id:
            answer_callback(callback_id, "Neustart verschoben")

        body, menu = render_view("updates")

        if chat_id and message_id:
            edit_telegram(chat_id, message_id, body, reply_markup=menu)
        return

    if str(data).strip() == "updates:reboot":
        if not reboot_required():
            if callback_id:
                answer_callback(callback_id, "Kein Neustart erforderlich")

            body, menu = render_view("updates")

            if chat_id and message_id:
                edit_telegram(chat_id, message_id, body, reply_markup=menu)
            return

        if callback_id:
            answer_callback(callback_id, "Neustart wird durchgeführt")

        if chat_id and message_id:
            edit_telegram(
                chat_id,
                message_id,
                "🔄 Neustart wird durchgeführt ...\n\n"
                "Der Proxmox-Host wird jetzt kontrolliert neu gestartet.",
                reply_markup={"inline_keyboard": []},
            )

        notify_other_admins(
            chat_id,
            f"ℹ️ {escape_tg(HOST_LABEL)}: Neustart wurde von {_actor_name(callback)} ausgelöst.",
        )

        threading.Thread(
            target=_reboot_worker,
            daemon=True,
            name="system-reboot-worker",
        ).start()
        return

    if str(data).strip() == "updates:confirm":
        if not _APT_INSTALL_LOCK.acquire(blocking=False):
            if callback_id:
                answer_callback(callback_id, "Installation läuft bereits")
            return

        snapshot = get_cached_snapshot()
        apt = snapshot.get("apt_updates", {}) or {}
        available = int(apt.get("available", 0) or 0)

        if available <= 0:
            _APT_INSTALL_LOCK.release()
            if callback_id:
                answer_callback(callback_id, "Keine Updates mehr verfügbar")
            return

        if callback_id:
            answer_callback(callback_id, "Installation gestartet")

        if chat_id and message_id:
            edit_telegram(
                chat_id,
                message_id,
                "📦 Updates installieren\n\n"
                f"⏳ {available} Update(s) werden installiert ...\n\n"
                "Bitte warten.\n"
                "Kein automatischer Reboot.",
                reply_markup={"inline_keyboard": []},
            )

        notify_other_admins(
            chat_id,
            f"ℹ️ {escape_tg(HOST_LABEL)}: Installation von {available} Update(s) "
            f"wurde von {_actor_name(callback)} gestartet.",
        )

        threading.Thread(
            target=_update_install_worker,
            args=(chat_id, message_id),
            daemon=True,
            name="apt-update-worker",
        ).start()
        return

    if data.startswith("wan_monthly:"):
        which = "current" if data.endswith(":current") else "previous"
        if callback_id:
            answer_callback(callback_id, "Bericht wird erstellt – kommt gleich als Datei")
        if not Path(MONTHLY_REPORT_SCRIPT).exists():
            send_telegram("⚠️ Monatsbericht ist noch nicht installiert.", chat_id=chat_id)
            return
        threading.Thread(
            target=_monthly_report_worker,
            args=(chat_id, which),
            daemon=True,
            name="monthly-report",
        ).start()
        return

    if data.startswith("refresh:"):
        parts = str(data or "").split(":", 1)

        if len(parts) < 2 or not parts[1].strip():
            log(f"Ungültige Callback-Daten: {data!r}")
            if callback_id:
                answer_callback(callback_id, "Ungültige Aktion")
            return

        view = parts[1].strip()

        if callback_id:
            answer_callback(callback_id, "")

        threading.Thread(
            target=_refresh_view_worker,
            args=(view, chat_id, message_id),
            daemon=True,
            name=f"refresh-{view}",
        ).start()
        return

    view = data

    if callback_id:
        answer_callback(callback_id, "")


    body, menu = render_view(view)


    if chat_id and message_id:
        # Unverändert-Prüfung je Chat UND Nachricht (vorher global ->
        # Account B bekam keine Aktualisierung, wenn A dieselbe Ansicht sah).
        if UI_STATE.is_unchanged(chat_id, message_id, body, view):
            return

        resp = edit_telegram(chat_id, message_id, body, reply_markup=menu)
        if isinstance(resp, dict) and resp.get("ok"):
            UI_STATE.remember_render(chat_id, message_id, body, view)
            UI_STATE.set_menu(chat_id, message_id, view)



def is_authorized(chat: dict, user: dict) -> bool:
    """Fail-closed: ohne konfigurierte IDs wird niemand autorisiert.

    Beide Accounts aus TELEGRAM_CHAT_IDS sind gleichberechtigt. In
    privaten Chats ist chat.id == user.id; in Gruppen muss zusätzlich
    der Absender selbst in der Liste stehen.
    """
    if not CHAT_IDS:
        return False
    chat_id = str((chat or {}).get("id", "")).strip()
    user_id = str((user or {}).get("id", "")).strip()
    if chat_id not in CHAT_IDS:
        return False
    if (chat or {}).get("type", "private") != "private" and user_id not in CHAT_IDS:
        return False
    return True


def poll_updates(poll_timeout=25):
    offset = load_offset()
    data = telegram_api("getUpdates", {
        "offset": offset + 1,
        "timeout": poll_timeout,
        "allowed_updates": ["message", "callback_query"]
    })
    if not data or not data.get("ok"):
        # Netzwerkfehler: kurz warten, um keine Schleife ohne Pause zu erzeugen
        time.sleep(5)
        return

    for upd in data.get("result", []):
        update_id = upd.get("update_id", 0)
        if update_id:
            save_offset(update_id)

        try:
            if "message" in upd:
                msg = upd.get("message", {})
                text = (msg.get("text", "") or "").strip()
                chat = msg.get("chat", {}) or {}
                chat_id = str(chat.get("id", "")).strip()
                message_id = msg.get("message_id")
                if not is_authorized(chat, msg.get("from", {})):
                    log(f"Nicht autorisierte Nachricht ignoriert: chat_id={chat_id}")
                    continue
                if text:
                    handle_message_command(text, chat_id, message_id=message_id)

            elif "callback_query" in upd:
                callback = upd.get("callback_query", {})
                chat = callback.get("message", {}).get("chat", {}) or {}
                if not is_authorized(chat, callback.get("from", {})):
                    log(f"Nicht autorisierter Callback ignoriert: chat_id={chat.get('id')}")
                    if callback.get("id"):
                        answer_callback(callback["id"], "Nicht berechtigt")
                    continue
                handle_callback(callback)
        except Exception as exc:
            # Ein fehlerhaftes Update darf weder den Batch noch den Loop stoppen
            log(f"Fehler bei Update {update_id}: {exc}")
            logger.debug(traceback.format_exc())










def guardian_run_inline(oldsnapshot, newsnapshot):
    snapshot = guardian_extract_snapshot(oldsnapshot, newsnapshot)

    alerts, bundle = build_guardian_bundle(oldsnapshot, snapshot)

    snapshot["guardian_alert_engine"] = (
        bundle.get("guardian_alert_engine", {}) or {}
    )
    snapshot["guardian_meta"] = (
        bundle.get("guardian_meta", {}) or {}
    )

    snapshot.update({
        "health": bundle.get("health", "unknown"),
        "health_score": bundle.get("health_score", 100),
        "health_counts": bundle.get("counts", {}),
        "guardian_summary": bundle.get("summary", {}),
    })

    return alerts, snapshot

from guardian_config import NOTIFY_WARNING_CATEGORIES as ALLOWED_WARNING_CATEGORIES  # noqa: E402

MAX_SENT_HASHES = 500


def _deliver_to_all(text, reply_markup=None):
    """Sendet an alle berechtigten Accounts. Fehlgeschlagene Zustellungen
    landen in der Outbox und werden später nachgeliefert."""
    for recipient in CHAT_IDS:
        resp = send_telegram(text, chat_id=recipient, reply_markup=reply_markup)
        if not (isinstance(resp, dict) and resp.get("ok")):
            OUTBOX.add(recipient, text, reply_markup)
            log(f"Alarm nicht zustellbar an {recipient} – in Outbox gespeichert")


def _outbox_sender(chat_id, text, reply_markup):
    resp = send_telegram(text, chat_id=chat_id, reply_markup=reply_markup)
    return isinstance(resp, dict) and resp.get("ok")


def run_monitor_cycle():
    """Ein vollständiger Prüfzyklus: Snapshot, Alert-Engine, Benachrichtigung."""
    # Zuerst ausstehende Alarme nachliefern (z. B. nach Internet-Ausfall)
    if OUTBOX.pending():
        delivered = OUTBOX.flush(_outbox_sender, log)
        if delivered:
            log(f"Outbox: {delivered} verspätete Nachricht(en) zugestellt")

    old_snapshot = get_cached_snapshot()
    new_snapshot = build_snapshot(old_snapshot)

    if not old_snapshot:
        log("Guardian First Run - Snapshot aufgebaut")

    try:
        guardian_outgoing, guardian_snapshot = guardian_run_inline(old_snapshot, new_snapshot)

        # First-Run-Schutz: bereits bekannte Alerts nicht erneut senden
        if not old_snapshot.get("guardian_initialized"):
            existing = set(
                (old_snapshot.get("guardian_alert_engine", {}) or {})
                .get("active", {})
                .keys()
            )
            guardian_outgoing = [
                a for a in guardian_outgoing
                if a.get("recovered") or a.get("hash") not in existing
            ]
            guardian_snapshot.setdefault("guardian_meta", {})["initialized"] = True

        new_snapshot["guardian_alert_engine"] = guardian_snapshot.get("guardian_alert_engine", {})
        new_snapshot["guardian_meta"] = guardian_snapshot.get("guardian_meta", {})
        new_snapshot["health"] = guardian_snapshot.get("health", new_snapshot.get("health", 100))
        new_snapshot["health_score"] = guardian_snapshot.get("health_score", 100)
        new_snapshot["health_counts"] = guardian_snapshot.get(
            "health_counts", guardian_snapshot.get("counts", {})
        )
        new_snapshot["guardian_summary"] = guardian_snapshot.get(
            "guardian_summary", guardian_snapshot.get("summary", {})
        )
        engine = new_snapshot.get("guardian_alert_engine", {}) or {}
        new_snapshot["guardian_alerts_active"] = engine.get("active", {}) or {}
        new_snapshot["guardian_alerts_recent"] = (engine.get("history", []) or [])[-20:]
        new_snapshot["alerts"] = list((engine.get("active", {}) or {}).values())
        new_snapshot["alert_count"] = len(new_snapshot["alerts"])
        new_snapshot["guardian_initialized"] = True

        log(
            f"outgoing={len(guardian_outgoing)} "
            f"active={len(new_snapshot.get('guardian_alerts_active', {}) or {})} "
            f"score={new_snapshot.get('health_score')} "
            f"counts={new_snapshot.get('health_counts')}"
        )

        guardian_meta = new_snapshot.setdefault("guardian_meta", {})
        sent_hashes = list(guardian_meta.get("sent_hashes", []))

        health = guardian_snapshot.get("health", "unknown")
        score = guardian_snapshot.get("health_score", "?")
        counts = guardian_snapshot.get("counts", {}) or {}
        health_icon = {"ok": "🟢", "warning": "🟡", "critical": "🔴"}.get(str(health).lower(), "⚪")
        health_text = (
            f"{health_icon} Health: {score}/100\n"
            f"Critical: {counts.get('critical', 0)} | "
            f"Warning: {counts.get('warning', 0)}"
        )

        for guardian_alert in guardian_outgoing:
            severity = str(guardian_alert.get("severity", "")).lower()
            category = str(guardian_alert.get("category", "")).lower()
            is_recovery = bool(
                guardian_alert.get("recovered")
                or guardian_alert.get("status") in ("recovered", "recovery")
            )

            if not is_recovery and severity not in {"critical", "warning"}:
                log(f"Guardian FILTER severity={severity} title={guardian_alert.get('title')}")
                continue

            if severity == "warning" and category not in ALLOWED_WARNING_CATEGORIES:
                log(f"Guardian FILTER category={category} title={guardian_alert.get('title')}")
                continue

            h = guardian_alert.get("hash")
            telegram_sent = bool(guardian_alert.get("telegram_sent", False))
            if h and h in sent_hashes and telegram_sent and not is_recovery:
                continue

            log(f"Guardian SEND: {guardian_alert.get('category')}/{guardian_alert.get('severity')} "
                f"{guardian_alert.get('title')} recovery={is_recovery}")

            # Alarmtexte enthalten u. a. "<95%" -> ohne Escaping lehnt
            # Telegram die HTML-Nachricht ab und der Alarm geht verloren.
            body = escape_tg(format_professional_alert(guardian_alert))

            reply_markup = None
            if guardian_alert.get("title") == "Neustart erforderlich" and not is_recovery:
                reply_markup = {
                    "inline_keyboard": [
                        [{"text": "🔄 Jetzt neu starten", "callback_data": "updates:reboot"}],
                        [{"text": "⏰ Später", "callback_data": "updates:reboot_cancel"}],
                    ]
                }

            _deliver_to_all(
                f"🛡️ {escape_tg(HOST_LABEL)}\n\n{health_text}\n\n{body}",
                reply_markup=reply_markup,
            )

            if h and h not in sent_hashes:
                sent_hashes.append(h)

        guardian_meta["sent_hashes"] = sent_hashes[-MAX_SENT_HASHES:]
        new_snapshot["guardian_meta"] = guardian_meta

    except Exception as guardian_exc:
        log(f"Guardian Engine Fehler: {guardian_exc}")
        log(traceback.format_exc())
        # Engine-Zustand des letzten Zyklus nicht verlieren
        for key in ENGINE_KEYS:
            if key in old_snapshot and key not in new_snapshot:
                new_snapshot[key] = old_snapshot[key]

    with SNAPSHOT_LOCK:
        save_snapshot_cache(new_snapshot)
        save_json(STATE_FILE, new_snapshot)


def monitor_loop():
    """Prüfzyklus im eigenen Thread – blockiert die Telegram-Bedienung nicht mehr."""
    global last_check_ts
    while True:
        started = time.time()
        try:
            run_monitor_cycle()
        except Exception as e:
            log(f"Monitor-Zyklus Fehler: {e}")
            log(traceback.format_exc())
        last_check_ts = started
        duration = time.time() - started
        if duration > CHECK_INTERVAL * 0.5:
            log(f"Monitor-Zyklus dauerte {duration:.1f} s (Intervall {CHECK_INTERVAL} s)")
        time.sleep(max(5.0, CHECK_INTERVAL - duration))


def main():
    log(f"Monitor gestartet (Intervall {CHECK_INTERVAL} s, berechtigte Chats: {len(CHAT_IDS)})")
    env_interval = os.getenv("CHECK_INTERVAL_SECONDS")
    if env_interval and env_interval.strip() != str(CHECK_INTERVAL):
        log(f"Hinweis: CHECK_INTERVAL_SECONDS={env_interval.strip()} wird ignoriert, "
            f"Prüfintervall ist fest {CHECK_INTERVAL} s.")

    threading.Thread(target=monitor_loop, daemon=True, name="monitor-loop").start()

    # Telegram-Bedienung im Hauptthread (Long-Polling, sofortige Reaktion)
    while True:
        try:
            if CHAT_IDS:
                poll_updates()
            else:
                time.sleep(30)
        except Exception as e:
            log(f"Poll-Loop Fehler: {e}")
            log(traceback.format_exc())
            time.sleep(5)



def get_backup_status(snapshot=None):
    def run(cmd):
        # Timeout: ein nicht erreichbarer Backup-Storage (NFS/PBS) darf den
        # Prüfzyklus nicht dauerhaft blockieren.
        try:
            return subprocess.check_output(
                cmd, shell=True, text=True, stderr=subprocess.DEVNULL, timeout=60
            ).strip()
        except Exception:
            return ""

    def parse_table_lines(raw):
        lines = [line.rstrip() for line in raw.splitlines() if line.strip()]
        if len(lines) <= 1:
            return []
        return lines[1:]

    storage_cfg = Path("/etc/pve/storage.cfg")
    backup_storages = []

    if storage_cfg.exists():
        current_name = None
        for line in storage_cfg.read_text(encoding="utf-8").splitlines():
            s_line = line.strip()
            if not s_line:
                continue
            if not line.startswith((" ", "\t")) and ":" in line:
                head = s_line.split(":", 1)
                current_name = head[1].strip()
            elif s_line.startswith("content "):
                current_content = s_line.replace("content ", "", 1).strip()
                if "backup" in [x.strip() for x in current_content.split(",")] and current_name:
                    backup_storages.append(current_name)

    qemu_ids = []
    for line in parse_table_lines(run("qm list")):
        parts = line.split()
        if parts:
            qemu_ids.append(parts[0])

    lxc_ids = []
    for line in parse_table_lines(run("pct list")):
        parts = line.split()
        if parts:
            lxc_ids.append(parts[0])

    total_backups = 0
    latest_overall = None
    storage_sections = []

    for storage in backup_storages:
        rows = parse_table_lines(run(f"pvesm list {storage}"))
        storage_count = 0
        used_ids = set()
        latest_ts = None

        for row in rows:
            if "backup/" not in row and "vzdump-" not in row:
                continue

            storage_count += 1
            parts = row.split()
            volid = parts[0] if parts else ""

            if "vzdump-qemu-" in volid:
                try:
                    used_ids.add(f"VM {volid.split('vzdump-qemu-')[1].split('-')[0]}")
                except Exception:
                    pass
            elif "vzdump-lxc-" in volid:
                try:
                    used_ids.add(f"LXC {volid.split('vzdump-lxc-')[1].split('-')[0]}")
                except Exception:
                    pass

            try:
                if "vzdump-" in volid:
                    stamp = volid.rsplit("-", 2)[-2] + "-" + volid.rsplit("-", 2)[-1]
                    stamp = stamp.replace(".vma.zst", "").replace(".tar.zst", "").replace(".vma.lzo", "").replace(".tar.lzo", "").replace(".vma.gz", "").replace(".tar.gz", "")
                    dt = datetime.strptime(stamp, "%Y_%m_%d-%H_%M_%S")
                    if latest_ts is None or dt > latest_ts:
                        latest_ts = dt
                    if latest_overall is None or dt > latest_overall:
                        latest_overall = dt
                elif len(parts) >= 3:
                    candidate = (parts[-2] + " " + parts[-1]).strip()
                    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
                        try:
                            dt = datetime.strptime(candidate, fmt)
                            if latest_ts is None or dt > latest_ts:
                                latest_ts = dt
                            if latest_overall is None or dt > latest_overall:
                                latest_overall = dt
                            break
                        except Exception:
                            pass
            except Exception:
                pass

        total_backups += storage_count

        section = [f"{storage.upper():<12} {storage_count:>3} Backups"]
        if latest_ts:
            section.append(f"{'Last':<12} {latest_ts.strftime('%d.%m.%Y %H:%M')}")
        else:
            section.append(f"{'Last':<12} unbekannt")

        for item in sorted(
            used_ids,
            key=lambda x: int(x.split()[1]) if len(x.split()) > 1 and x.split()[1].isdigit() else 999999
        )[:10]:
            section.append(f"{item[:28]}")
        if len(used_ids) > 10:
            section.append(f"... {len(used_ids) - 10} weitere")

        storage_sections.append(section)

    status = "OK" if backup_storages else "FAIL"
    now = datetime.now().strftime("%d.%m.%Y %H:%M")
    latest_text = latest_overall.strftime("%d.%m.%Y %H:%M") if latest_overall else "unbekannt"

    table = [
        "BACKUP",
        f"{'Status':<12} {status}",
        f"{'Prüfung':<12} {now}",
        f"{'Letztes':<12} {latest_text}",
        "",
        "ÜBERSICHT",
        f"{'QEMU':<12} {len(qemu_ids)}",
        f"{'LXC':<12} {len(lxc_ids)}",
        f"{'Storages':<12} {len(backup_storages)}",
        f"{'Backups':<12} {total_backups}",
    ]

    if storage_sections:
        table.append("")
        table.append("STORAGES")
        for idx, section in enumerate(storage_sections):
            if idx:
                table.append("")
            table.extend(section)
    else:
        table.append("")
        table.append("Keine Backup-Daten gefunden.")

    return "\n".join(table)

    return "\n".join([
        "📦 Backup",
        "",
        f"<pre>{chr(10).join(table)}</pre>",
    ])

def guardian_extract_snapshot(oldsnapshot, newsnapshot):
    base = {}
    if isinstance(newsnapshot, dict):
        base.update(newsnapshot)
    elif isinstance(oldsnapshot, dict):
        base.update(oldsnapshot)

    status = {}
    if isinstance(newsnapshot, dict):
        status = newsnapshot.get("status", {}) or {}

    cpu = 0.0
    try:
        raw_cpu = status.get("cpu", base.get("cpu", 0)) or 0
        raw_cpu = float(raw_cpu)
        cpu = raw_cpu * 100.0 if raw_cpu <= 1.0 else raw_cpu
    except Exception:
        cpu = 0.0

    rootfs = base.get("rootfs")
    if not isinstance(rootfs, dict):
        rootfs = {}

    if not rootfs and isinstance(newsnapshot, dict):
        for item in (newsnapshot.get("storage", []) or []):
            try:
                if str(item.get("storage", "")).lower() in ("local", "rootdir", "rootfs"):
                    total = float(item.get("total", 0) or 0)
                    used = float(item.get("used", 0) or 0)
                    pct = (used / total * 100.0) if total > 0 else 0.0
                    rootfs = {"percent": pct, "used": used, "total": total}
                    break
            except Exception:
                continue

    snap = {
        "cpu": cpu,
        "rootfs": rootfs,
        "node": base.get("node") or base.get("hostname") or base.get("host"),
        "hostname": base.get("hostname") or base.get("node") or base.get("host"),

        # Netzwerkstatus für Guardian übernehmen
        "internetonline": base.get(
            "internetonline",
            base.get("internet_online", True)
        ),
        "dnsok": base.get(
            "dnsok",
            base.get("dns_ok", True)
        ),
        "telegramonline": base.get(
            "telegramonline",
            base.get("telegram_online", True)
        ),

        "wanip": base.get("wanip"),

        # Proxmox API / Node Status für Guardian übernehmen
        "nodestatus": {
            "status": (
                base.get("node_resources", [{}])[0].get("status")
                if isinstance(base.get("node_resources"), list)
                and base.get("node_resources")
                else "unknown"
            ),
            "raw": base.get("node_status", {}),
        },
        "version": base.get("version", {}),
        "node_resources": base.get("node_resources", []),

        "ram": base.get("ram", 0),
        "rebootrequired": base.get(
            "reboot_required",
            base.get("rebootrequired", False)
        ),
        "tasks": base.get("tasks", []),
        "failed_tasks": base.get("failed_tasks", []),

        "qemu": base.get("qemu", []),
        "lxc": base.get("lxc", []),

        "storages": base.get("storages", []),
        "smart": base.get("smart", []),
        "zfs_status": base.get("zfs_status", "Kein ZFS oder nicht verfügbar"),

        "guardian_source": "monitor.py",
    }

    # Guardian State wird nicht mehr aus altem Snapshot übernommen.
    # Die Alert Engine verwaltet ihren eigenen Zustand.
    snap["guardian_alert_engine"] = {}

    return snap


if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    main()

