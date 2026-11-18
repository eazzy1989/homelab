#!/usr/bin/env python3
from __future__ import annotations

from typing import Any

from guardian_alerts import make_alert
from guardian_helpers import safe_str


def build_api_alerts(snapshot: dict[str, Any] | None) -> list[dict[str, Any]]:
    snapshot = snapshot or {}
    out: list[dict[str, Any]] = []

    nodestatus = snapshot.get("nodestatus", {}) or {}

    if not nodestatus:
        resources = snapshot.get("node_resources", []) or []
        if resources and isinstance(resources[0], dict):
            nodestatus = {
                "status": resources[0].get("status", "unknown"),
                "raw": snapshot.get("node_status", {})
            }

    version = snapshot.get("version", {}) or {}

    if isinstance(nodestatus, dict):
        if safe_str(nodestatus.get("status"), "").lower() not in ("online", "ok", "running"):
            out.append(make_alert(
                category="api",
                severity="critical",
                title="Proxmox Node API auffällig",
                description="Die Node-API meldet keinen normalen Status.",
                cause=safe_str(nodestatus.get("status"), "unknown"),
                solution="API, pveproxy und pvedaemon prüfen.",
                diagnosis=["systemctl status pveproxy pvedaemon", "journalctl -u pveproxy -n 100 --no-pager", "journalctl -u pvedaemon -n 100 --no-pager"],
                file_path=["/etc/pve", "/var/lib/pve-cluster"],
                log_file=["/var/log/syslog", "journalctl -u pveproxy -n 100 --no-pager"],
                recovery_hint="API muss wieder normal antworten.",
                source="API-Check",
                entity=safe_str(snapshot.get("node"), "pve"),
                metric="node_status",
                threshold="online/ok/running",
                current_value=safe_str(nodestatus.get("status"), "unknown"),
                summary="Proxmox Node API auffällig",
            ))

    if isinstance(version, dict) and not version:
        out.append(make_alert(
            category="api",
            severity="warning",
            title="Proxmox Version fehlt",
            description="Die Versionsabfrage liefert keine verwertbaren Daten.",
            cause="leeres version payload",
            solution="Proxmox API und Authentifizierung prüfen.",
            diagnosis=["pveversion -v", "curl -k https://127.0.0.1:8006/api2/json/version"],
            file_path=["/etc/pve"],
            log_file=["/var/log/syslog", "journalctl -u pveproxy -n 100 --no-pager"],
            recovery_hint="Version muss wieder verfügbar sein.",
            source="API-Check",
            entity=safe_str(snapshot.get("node"), "pve"),
            metric="version",
            threshold="non-empty",
            current_value="empty",
            summary="Proxmox Version fehlt",
        ))

    return out
