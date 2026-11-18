from __future__ import annotations

import json
import logging
import os
import subprocess
import socket
import requests
import re
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger("proxmox_guardian.utils")

# Kein Shell-Befehl darf den Prüfzyklus unbegrenzt blockieren
# (z. B. smartctl auf schlafender Platte, pvesm auf offline-NFS).
DEFAULT_CMD_TIMEOUT = 60


def _run_cmd(cmd: str, timeout: int = DEFAULT_CMD_TIMEOUT) -> str:
    try:
        return subprocess.check_output(
            cmd,
            shell=True,
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
        ).strip()
    except subprocess.TimeoutExpired:
        logger.warning("Befehl nach %s s abgebrochen: %s", timeout, cmd[:120])
        return ""
    except Exception:
        return ""


def _json_cmd(cmd: str):
    raw = _run_cmd(cmd)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None


def _read_first_existing(paths):
    for path in paths:
        try:
            p = Path(path)
            if p.exists():
                return p.read_text(
                    encoding="utf-8",
                    errors="ignore",
                ).strip()
        except Exception:
            pass
    return ""


def _fmt_bytes(num):
    try:
        num = float(num)
    except Exception:
        return "unbekannt"
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    for unit in units:
        if abs(num) < 1024.0 or unit == units[-1]:
            if unit == "B":
                return f"{int(num)} {unit}"
            return f"{num:.1f} {unit}"
        num /= 1024.0
    return "unbekannt"


def _fmt_pct(used, total):
    try:
        used = float(used)
        total = float(total)
        if total <= 0:
            return "0 %"
        return f"{(used / total) * 100:.0f} %"
    except Exception:
        return "unbekannt"


def _fmt_duration(seconds):
    try:
        seconds = int(float(seconds))
    except Exception:
        return "unbekannt"
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts)


def _detect_node(snapshot=None):
    if isinstance(snapshot, dict):
        for key in ("node", "hostname", "host"):
            val = snapshot.get(key)
            if val:
                return str(val).strip()
    return _run_cmd("hostname -s") or "localhost"


def _run_backup_cmd(cmd: str) -> str:
    return _run_cmd(cmd, timeout=DEFAULT_CMD_TIMEOUT)


def _parse_table_lines(raw: str) -> list[str]:
    lines = [line.rstrip() for line in raw.splitlines() if line.strip()]
    if len(lines) <= 1:
        return []
    return lines[1:]


def _parse_vm_ids(raw_output: str) -> list[str]:
    ids = []
    for line in _parse_table_lines(raw_output):
        parts = line.split()
        if parts:
            ids.append(parts[0])
    return ids


def atomic_write_json(path, data):
    # Eindeutiger Temp-Name: Monitor-Thread und Refresh-Worker schreiben ggf. gleichzeitig
    tmp = f"{path}.{os.getpid()}.{threading_ident()}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())
    Path(tmp).replace(path)


def threading_ident() -> int:
    import threading
    return threading.get_ident()


def load_json(path, default=None):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {} if default is None else default


def save_json(path, data):
    atomic_write_json(path, data)


def load_offset():
    return load_json("telegram_offset.json", {"offset": 0}).get("offset", 0)


def save_offset(offset):
    save_json("telegram_offset.json", {"offset": offset})


def run_cmd(cmd):
    return _run_cmd(cmd)


def run_cmd_result(cmd, timeout=900):
    """Führt einen Systembefehl kontrolliert aus und liefert Exit-Code + Ausgabe."""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
        return {
            "returncode": result.returncode,
            "output": (result.stdout or "").strip(),
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        if isinstance(output, bytes):
            output = output.decode(errors="replace")
        return {
            "returncode": -1,
            "output": str(output).strip(),
            "timed_out": True,
        }
    except Exception as exc:
        return {
            "returncode": -1,
            "output": str(exc),
            "timed_out": False,
        }


def install_apt_updates(timeout=1800):
    """Installiert verfügbare APT-Updates kontrolliert.
    
    Diese Funktion führt keinen Reboot aus.
    """
    lock_paths = (
        "/var/lib/dpkg/lock-frontend",
        "/var/lib/dpkg/lock",
        "/var/lib/apt/lists/lock",
    )

    lock_check = subprocess.run(
        ["fuser", "-v", *lock_paths],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    if lock_check.returncode == 0 and lock_check.stdout.strip():
        return {
            "success": False,
            "stage": "lock",
            "output": "APT/dpkg ist aktuell gesperrt.\n" + lock_check.stdout.strip(),
        }

    update = run_cmd_result(
        "DEBIAN_FRONTEND=noninteractive apt-get update",
        timeout=600,
    )

    if update["returncode"] != 0:
        return {
            "success": False,
            "stage": "update",
            "output": update["output"],
        }

    upgrade = run_cmd_result(
        "DEBIAN_FRONTEND=noninteractive "
        "apt-get full-upgrade -y "
        "-o Dpkg::Options::=--force-confold",
        timeout=timeout,
    )

    output = upgrade["output"] or ""

    # Entscheidend ist der tatsächliche Zustand NACH der Installation.
    # Die APT-Zeile "N not upgraded" kann auch Pakete enthalten,
    # die nach dem Full-Upgrade nicht mehr als offen geführt werden.
    remaining = run_cmd_result(
        "apt list --upgradable 2>/dev/null",
        timeout=60,
    )

    remaining_output = remaining["output"] or ""
    remaining_packages = [
        line.strip()
        for line in remaining_output.splitlines()
        if line.strip()
        and not line.startswith("Listing...")
        and "/" in line
    ]

    if remaining["returncode"] != 0:
        success = False
        output += (
            "\n\nGuardian: Prüfung der verbleibenden Updates "
            "konnte nicht durchgeführt werden."
        )
    else:
        success = upgrade["returncode"] == 0 and not remaining_packages

        if remaining_packages:
            output += (
                "\n\nGuardian: Es sind noch "
                f"{len(remaining_packages)} Update(s) verfügbar:\n"
                + "\n".join(remaining_packages[:20])
            )

    return {
        "success": success,
        "stage": "full-upgrade",
        "output": output,
    }


def fmt_gb(value):
    try:
        return f"{float(value):.1f} GB"
    except Exception:
        return "?"


def format_uptime_seconds(seconds):
    seconds = int(seconds or 0)
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def get_load():
    try:
        load = os.getloadavg()
        return load[0], load[1], load[2]
    except Exception:
        return 0, 0, 0


def get_kernel():
    return _run_cmd("uname -r").strip()



def get_apt_updates():
    """Liefert verfügbare APT-Updates dynamisch als strukturierte Daten."""
    raw = _run_cmd("apt list --upgradable 2>/dev/null")
    lines = [
        line.strip()
        for line in raw.splitlines()
        if line.strip() and not line.startswith("Listing")
    ]

    packages = []
    for line in lines:
        name = line.split("/", 1)[0].strip()
        if name:
            packages.append(name)

    security = sum(
        1
        for line in lines
        if "security" in line.lower()
    )

    return {
        "available": len(packages),
        "security": security,
        "packages": packages,
    }

def reboot_required():
    """
    Erkennt einen ausstehenden Neustart auf Proxmox.

    True wenn:
    - der offizielle Debian/Ubuntu-Reboot-Marker existiert oder
    - ein neuerer installierter Proxmox-Kernel vorhanden ist
      als der aktuell laufende Kernel.
    """
    # Offizieller Reboot-Marker
    if Path("/var/run/reboot-required").exists():
        return True

    # Aktuell laufender Kernel
    current = get_kernel()
    if not current:
        return False

    # Installierte Proxmox-Kernel prüfen
    for kernel_path in Path("/boot").glob("vmlinuz-*-pve"):
        installed = kernel_path.name.removeprefix("vmlinuz-")

        if not installed or installed == current:
            continue

        # Debian/Proxmox-Versionsvergleich verwenden.
        # Das ist robuster als die Kernel-Version selbst zu zerlegen.
        result = subprocess.run(
            ["dpkg", "--compare-versions", installed, "gt", current],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )

        if result.returncode == 0:
            return True

    return False


import shutil


def get_rootfs():
    try:
        disk = shutil.disk_usage("/")
        total = round(disk.total / (1024**3), 1)
        used = round(disk.used / (1024**3), 1)
        free = round(disk.free / (1024**3), 1)
        pct = round((disk.used / disk.total) * 100, 1)
        return {
            "total_gb": total,
            "used_gb": used,
            "free_gb": free,
            "percent": pct,
        }
    except Exception:
        return {
            "total_gb": 0,
            "used_gb": 0,
            "free_gb": 0,
            "percent": 0,
        }


def get_storage_local():
    raw = run_cmd("pvesm status 2>/dev/null")
    rows = []
    if not raw:
        return rows

    for line in raw.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        try:
            rows.append({
                "storage": parts[0],
                "type": parts[1],
                "total": int(parts[2]) * 1024,
                "used": int(parts[3]) * 1024,
                "avail": int(parts[4]) * 1024,
                "percent": parts[5],
            })
        except Exception:
            pass

    return rows


import psutil


def get_cpu_temp():
    try:
        temps = psutil.sensors_temperatures()
        for group in temps.values():
            for entry in group:
                if entry.current is not None:
                    return round(entry.current, 1)
    except Exception:
        pass
    return None


def get_all_temps():
    results = []
    try:
        temps = psutil.sensors_temperatures()
        for chip, entries in temps.items():
            for entry in entries:
                label = entry.label or chip
                current = entry.current if entry.current is not None else "n/a"
                results.append(f"{label}: {current} °C")
    except Exception:
        pass
    return results


def get_smart_summary():
    out = run_cmd("which smartctl && lsblk -dno NAME,TYPE | awk '$2==\"disk\"{print $1}'")
    if not out:
        return []

    disks = []
    for dev in out.splitlines():
        health = run_cmd(
            f"smartctl -H /dev/{dev} | grep -i 'SMART overall-health\\|SMART Health Status\\|result'"
        )
        if health:
            disks.append({
                "device": f"/dev/{dev}",
                "health": health,
            })

    return disks[:8]


def get_zfs_status():
    status = run_cmd("which zpool >/dev/null 2>&1 && zpool status -x")
    return status or "Kein ZFS oder nicht verfügbar"


def internet_online():
    try:
        socket.create_connection(("1.1.1.1", 53), timeout=3).close()
        return True
    except Exception:
        return False


def telegram_online():
    try:
        r = requests.get("https://api.telegram.org", timeout=5)
        return 200 <= r.status_code < 400
    except Exception:
        return False


def dns_ok():
    try:
        socket.gethostbyname("api.telegram.org")
        return True
    except Exception:
        return False


def get_lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "unbekannt"


def get_interfaces() -> list[str]:
    rows = []
    try:
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    mask = addr.netmask or ""
                    cidr = sum(bin(int(x)).count("1") for x in mask.split(".")) if mask else ""
                    suffix = f"/{cidr}" if cidr != "" else ""
                    rows.append(f"- {iface}: {addr.address}{suffix}")
    except Exception as e:
        logger.warning("Interfaces konnten nicht gelesen werden: %s", e)
    return rows


def ping_target(target: str) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            ["/bin/ping", "-c", "1", "-W", "1", target],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
        )
        out = (proc.stdout or "") + "\n" + (proc.stderr or "")
        m = re.search(r'time=([0-9]+(?:\.[0-9]+)?)\s*ms', out)
        if proc.returncode == 0:
            return {"target": target, "ok": True, "latency_ms": float(m.group(1)) if m else None}
        return {"target": target, "ok": False, "latency_ms": None, "error": out.strip()}
    except Exception as e:
        return {"target": target, "ok": False, "latency_ms": None, "error": str(e)}


def tcp_port_check(host: str, port: int, timeout: float = 1.5) -> dict[str, Any]:
    start = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            latency_ms = (time.time() - start) * 1000
            return {"ok": True, "latency_ms": round(latency_ms, 1)}
    except Exception:
        return {"ok": False, "latency_ms": None}


def _parse_backup_storages(cfg_path: str | Path) -> list[str]:
    cfg = Path(cfg_path)
    storages: list[str] = []
    if not cfg.exists():
        return storages

    current_name = None
    for line in cfg.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s:
            continue
        if not line.startswith((" ", "\t")) and ":" in line:
            head = s.split(":", 1)
            current_name = head[1].strip()
        elif s.startswith("content "):
            current_content = s.replace("content ", "", 1).strip()
            if "backup" in [x.strip() for x in current_content.split(",")] and current_name:
                storages.append(current_name)
    return storages


def _extract_guest_from_volid(volid: str) -> str | None:
    try:
        if "vzdump-qemu-" in volid:
            parts = volid.split("vzdump-qemu-", 1)
            if len(parts) > 1 and "-" in parts[1]:
                return f"VM {parts[1].split('-', 1)[0]}"
            return "VM unbekannt"
        if "vzdump-lxc-" in volid:
            parts = volid.split("vzdump-lxc-", 1)
            if len(parts) > 1 and "-" in parts[1]:
                return f"LXC {parts[1].split('-', 1)[0]}"
            return "LXC unbekannt"
    except Exception as e:
        logger.warning("VolID konnte nicht geparst werden: %s | volid=%s", e, volid)
    return None


def _count_backups_for_storage(storage: str) -> tuple[int, set[str]]:
    out = _run_backup_cmd(f"pvesm list {storage}")
    lines = _parse_table_lines(out)
    storage_count = 0
    used_ids: set[str] = set()

    for line in lines:
        if "backup/" not in line and "vzdump-" not in line:
            continue
        storage_count += 1
        parts = line.split()
        volid = parts[0] if parts else ""
        guest = _extract_guest_from_volid(volid)
        if guest:
            used_ids.add(guest)

    return storage_count, used_ids


def _list_running_tasks(node):
    data = _json_cmd(f"pvesh get /nodes/{node}/tasks --output-format json")
    if not isinstance(data, list):
        return []
    return [item for item in data if str(item.get("status", "")).lower() == "running"]


def _list_failed_tasks(node, limit=5):
    data = _json_cmd(f"pvesh get /nodes/{node}/tasks --output-format json")
    if not isinstance(data, list):
        return []
    failed = []
    for item in data:
        status = str(item.get("status", "")).lower()
        exitstatus = str(item.get("exitstatus", "")).lower()
        if "error" in status or (exitstatus and exitstatus not in ("ok", "unknown")):
            failed.append(item)
    return failed[:limit]
