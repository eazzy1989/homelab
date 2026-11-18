#!/usr/bin/env python3
from __future__ import annotations

from typing import Any

from guardian_alerts import make_alert
from guardian_helpers import safe_str


def build_network_alerts(snapshot: dict[str, Any] | None) -> list[dict[str, Any]]:
    snapshot = snapshot or {}
    host = safe_str(snapshot.get("host"), "Proxmox")
    node = safe_str(snapshot.get("node") or snapshot.get("hostname"), "node")
    out: list[dict[str, Any]] = []

    if not bool(snapshot.get("internet_online", snapshot.get("internetonline", False))):
        out.append(make_alert(
            category="network",
            severity="critical",
            title="Internet offline",
            description=f"Host {host}/{node} erreicht das Internet nicht.",
            cause="Externer Konnektivitätstest fehlgeschlagen.",
            solution="Gateway, Routing, Uplink und DNS-Basisfunktion prüfen.",
            diagnosis=["ip addr", "ip route", "ping -c 3 1.1.1.1", "traceroute 1.1.1.1"],
            file_path=["/etc/network/interfaces", "/etc/resolv.conf"],
            log_file=["/var/log/syslog", "journalctl -u networking -n 100 --no-pager"],
            recovery_hint="Internet-Konnektivität muss wiederhergestellt werden.",
            source="Internet-Check",
            entity="host",
            metric="internet",
            threshold="reachable = true",
            current_value="reachable = false",
            summary="Internet offline",
        ))

    if not bool(snapshot.get("dns_ok", snapshot.get("dnsok", False))):
        out.append(make_alert(
            category="network",
            severity="warning",
            title="DNS Fehler",
            description=f"DNS-Auflösung auf Host {host}/{node} funktioniert nicht.",
            cause="Namensauflösung für externe Ziele fehlgeschlagen.",
            solution="Resolver, Upstream-DNS und Netzwerkpfad prüfen.",
            diagnosis=["resolvectl status", "cat /etc/resolv.conf", "getent hosts api.telegram.org", "ping -c 3 8.8.8.8"],
            file_path=["/etc/resolv.conf", "/etc/hosts"],
            log_file=["/var/log/syslog", "journalctl -u systemd-resolved -n 100 --no-pager"],
            recovery_hint="DNS-Auflösung muss wieder funktionieren.",
            source="DNS-Check",
            entity="host",
            metric="dns",
            threshold="resolve = true",
            current_value="resolve = false",
            summary="DNS Fehler",
        ))

    if not bool(snapshot.get("telegram_online", snapshot.get("telegramonline", False))):
        out.append(make_alert(
            category="network",
            severity="warning",
            title="Telegram API nicht erreichbar",
            description=f"Telegram API ist von Host {host}/{node} aus nicht erreichbar.",
            cause="HTTP-Erreichbarkeit von api.telegram.org fehlgeschlagen.",
            solution="Internet, DNS, Firewall und Telegram-Zielpfad prüfen.",
            diagnosis=["ping -c 3 api.telegram.org", "resolvectl status", "curl -I https://api.telegram.org", "journalctl -u proxmox-monitor.service -n 100 --no-pager"],
            file_path=["/etc/resolv.conf", "/etc/network/interfaces"],
            log_file=["/var/log/syslog", "journalctl -u proxmox-monitor.service -n 100 --no-pager"],
            recovery_hint="Telegram API muss wieder erreichbar sein.",
            source="Telegram-Check",
            entity="host",
            metric="telegram_api",
            threshold="reachable = true",
            current_value="reachable = false",
            summary="Telegram API down",
        ))

    wan = safe_str(snapshot.get("wanip"))
    old_wan = safe_str(((snapshot.get("guardian_meta", {}) or {}).get("last_wanip")))
    if wan and old_wan and wan != old_wan:
        out.append(make_alert(
            category="network",
            severity="warning",
            title="WAN-IP geändert",
            description=f"Die WAN-IP von Host {host}/{node} hat sich geändert.",
            cause=f"Vorher {old_wan}, jetzt {wan}.",
            solution="Prüfen, ob die Änderung erwartet war und abhängige Freigaben/DNS aktualisieren.",
            diagnosis=["ip addr", "ip route", "curl -s https://api.ipify.org"],
            file_path=["/etc/network/interfaces"],
            log_file=["journalctl -u networking -n 100 --no-pager"],
            recovery_hint="Kein Recovery erforderlich; nur Informations-/Warnereignis.",
            source="WAN-IP-Check",
            entity="host",
            metric="wan_ip",
            threshold=f"!= {old_wan}",
            current_value=wan,
            summary="WAN-IP geändert",
        ))

    return out
