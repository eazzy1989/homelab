#!/usr/bin/env python3
from __future__ import annotations

from typing import Any
import subprocess
import time

from guardian_alerts import make_alert

# Vorübergehende systemd-Reloads nicht sofort als Ausfall melden.
RELOADING_GRACE_SECONDS = 60
_RELOADING_SINCE: dict[str, float] = {}


CORE_SERVICES = [
    ("pveproxy", "critical"),
    ("pvedaemon", "critical"),
    ("pvestatd", "warning"),
    ("pve-cluster", "critical"),
    ("sshd", "warning"),
]


def _service_state(service: str) -> str:
    try:
        result = subprocess.run(
            ["systemctl", "is-active", service],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        return result.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def _cluster_enabled() -> bool:
    try:
        out = subprocess.check_output(
            ["pvecm", "status"],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=15,
        )

        return "cluster name" in out.lower()

    except Exception:
        return False


def build_service_alerts(snapshot: dict[str, Any] | None) -> list[dict[str, Any]]:
    out=[]

    node = (snapshot or {}).get("node","pve")

    services = list(CORE_SERVICES)

    if _cluster_enabled():
        services.append(("corosync","critical"))

    for service, severity in services:
        state = _service_state(service)

        if state == "active":
            _RELOADING_SINCE.pop(service, None)
            continue

        if state == "reloading":
            now = time.monotonic()
            started = _RELOADING_SINCE.setdefault(service, now)

            if now - started < RELOADING_GRACE_SECONDS:
                continue
        else:
            _RELOADING_SINCE.pop(service, None)

        out.append(make_alert(
                category="service",
                severity=severity,
                title=f"Proxmox Dienst ausgefallen: {service}",
                description=f"Der Dienst {service} ist nicht aktiv.",
                cause=f"systemctl meldet Status: {state}",
                solution=f"Dienst prüfen und neu starten: systemctl restart {service}",
                diagnosis=[
                    f"systemctl status {service}",
                    f"journalctl -u {service} -n 100 --no-pager"
                ],
                file_path=[
                    "/etc/systemd/system",
                    "/etc/pve"
                ],
                log_file=[
                    f"journalctl -u {service}"
                ],
                recovery_hint="Dienst muss wieder aktiv sein.",
                source="Service-Check",
                entity=node,
                metric=service,
                threshold="active",
                current_value=state,
                summary=f"Dienst {service} nicht aktiv",
            ))

    return out
