#!/usr/bin/env python3
from __future__ import annotations

from typing import Any

from guardian_alerts import make_alert
from guardian_helpers import safe_str, clamp_float


def build_smart_alerts(snapshot: dict[str, Any] | None) -> list[dict[str, Any]]:
    snapshot = snapshot or {}
    smart_items = snapshot.get("smart", []) or []
    out: list[dict[str, Any]] = []

    for d in smart_items:
        device = safe_str(d.get("device"), "unknown")
        health = safe_str(d.get("health"), "unknown")
        temp = safe_str(d.get("temp") or d.get("temperature") or d.get("current"), "")
        model = safe_str(d.get("model"), "unknown")
        pending = clamp_float(d.get("pending", 0), 0.0, 0.0, 1000000.0)
        realloc = clamp_float(d.get("reallocated", 0), 0.0, 0.0, 1000000.0)
        offline = clamp_float(d.get("offline_uncorrectable", 0), 0.0, 0.0, 1000000.0)

        hu = health.upper()
        if hu and ("FAILED" in hu or "BAD" in hu or "FAIL" in hu):
            out.append(make_alert(
                category="smart",
                severity="critical",
                title=f"SMART Fehler: {device}",
                description=f"SMART meldet einen kritischen Zustand auf {device}.",
                cause=f"Health={health}, Model={model}.",
                solution="Disk sofort prüfen, Daten sichern, Laufwerk tauschen planen.",
                diagnosis=["smartctl -a /dev/sdX", "smartctl -H /dev/sdX", "dmesg -T | grep -iE 'smart|ata|io error'"],
                file_path=["/sys/block", "/dev/disk/by-id"],
                log_file=["/var/log/syslog", "/var/log/kern.log", "journalctl -k -n 200 --no-pager"],
                recovery_hint="Recovery erst nach ersetztem oder wieder gesundem Laufwerk.",
                source="SMART-Check",
                entity=device,
                metric="health",
                threshold="PASSED/OK",
                current_value=health,
                summary=f"SMART Fehler {device}",
                extra={"model": model, "temp": temp, "pending": pending, "reallocated": realloc, "offline_uncorrectable": offline},
            ))

        if pending > 0 or offline > 0:
            out.append(make_alert(
                category="smart",
                severity="critical",
                title=f"SMART Auffälligkeit: {device}",
                description=f"SMART-Zähler sind auf {device} auffällig.",
                cause=f"Pending={pending:.0f}, Reallocated={realloc:.0f}, OfflineUncorrectable={offline:.0f}.",
                solution="Diskzustand beobachten, Backup sicherstellen, Ausfallplan vorbereiten.",
                diagnosis=["smartctl -a /dev/sdX", "smartctl -H /dev/sdX", "dmesg -T | grep -iE 'smart|ata|io error'"],
                file_path=["/sys/block", "/dev/disk/by-id"],
                log_file=["/var/log/syslog", "/var/log/kern.log", "journalctl -k -n 200 --no-pager"],
                recovery_hint="Zähler müssen stabil bleiben oder zurückgehen.",
                source="SMART-Check",
                entity=device,
                metric="attributes",
                threshold="all counters = 0",
                current_value=f"pending={pending:.0f}, reallocated={realloc:.0f}, offline={offline:.0f}",
                summary=f"SMART Auffälligkeit {device}",
                extra={"model": model, "temp": temp, "pending": pending, "reallocated": realloc, "offline_uncorrectable": offline},
            ))

        if temp:
            try:
                t = float(str(temp).replace("C", "").replace("°", "").strip())

                if t >= 60:
                    severity="critical"
                elif t >= 50:
                    severity="warning"
                else:
                    severity=None

                if severity:
                    out.append(make_alert(
                        category="smart",
                        severity=severity,
                        title=f"Disk Temperatur hoch: {device}",
                        description=f"Die Temperatur von {device} ist kritisch hoch.",
                        cause=f"Aktuelle Temperatur {t:.1f} C.",
                        solution="Lüfter, Gehäusebelüftung und Umgebungstemperatur prüfen.",
                        diagnosis=["smartctl -A /dev/sdX", "sensors", "dmesg -T | tail -n 100"],
                        file_path=["/sys/class/thermal", "/sys/block"],
                        log_file=["/var/log/syslog", "journalctl -k -n 100 --no-pager"],
                        recovery_hint="Temperatur muss deutlich sinken.",
                        source="SMART-Temperature",
                        entity=device,
                        metric="temperature",
                        threshold="< 50C",
                        current_value=f"{t:.1f}C",
                        summary=f"SMART Temperatur kritisch {device}",
                        extra={"model": model},
                    ))
            except Exception:
                pass

    return out
