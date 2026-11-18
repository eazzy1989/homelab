#!/usr/bin/env python3
from __future__ import annotations

from typing import Any

from guardian_alerts import make_alert
from guardian_helpers import safe_str


def build_security_alerts(snapshot: dict[str, Any] | None) -> list[dict[str, Any]]:
    snapshot = snapshot or {}
    out: list[dict[str, Any]] = []

    updates = safe_str(snapshot.get("updatesstatus") or snapshot.get("securityupdates") or "")
    firewall = safe_str(snapshot.get("firewallstatus") or snapshot.get("firewall") or "")
    ssh = safe_str(snapshot.get("sshstatus") or snapshot.get("ssh") or "")

    if updates and any(x in updates.upper() for x in ("SECURITY", "UPGRADE", "REBOOT")):
        out.append(make_alert(
            category="updates",
            severity="warning",
            title="Security Updates",
            description="Sicherheitsrelevante Updates oder Reboot-Hinweise vorhanden.",
            cause=updates,
            solution="Updates zeitnah einspielen und Reboot-Bedarf prüfen.",
            diagnosis=["apt list --upgradable", "unattended-upgrades --dry-run", "needrestart"],
            file_path=["/var/lib/apt", "/etc/apt"],
            log_file=["/var/log/apt/history.log", "/var/log/dpkg.log", "journalctl -u apt-daily-upgrade -n 100 --no-pager"],
            recovery_hint="Alle relevanten Updates müssen installiert sein.",
            source="Updates-Check",
            entity=safe_str(snapshot.get("host"), "host"),
            metric="security_updates",
            threshold="none pending",
            current_value=updates,
            summary="Security Updates",
            extra={"raw": updates},
        ))

    if firewall and any(x in firewall.upper() for x in ("OFF", "ERROR", "FAIL", "STOP")):
        out.append(make_alert(
            category="security",
            severity="critical",
            title="Firewall Problem",
            description="Firewall ist gestört oder deaktiviert.",
            cause=firewall,
            solution="pve-firewall, nftables und Cluster-Firewall prüfen.",
            diagnosis=["pve-firewall status", "nft list ruleset", "iptables -S", "journalctl -u pve-firewall -n 100 --no-pager"],
            file_path=["/etc/pve/firewall", "/etc/nftables.conf"],
            log_file=["/var/log/syslog", "journalctl -u pve-firewall -n 100 --no-pager"],
            recovery_hint="Firewall muss wieder aktiv und fehlerfrei sein.",
            source="Firewall-Check",
            entity=safe_str(snapshot.get("host"), "host"),
            metric="firewall",
            threshold="active",
            current_value=firewall,
            summary="Firewall Problem",
            extra={"raw": firewall},
        ))

    if ssh and any(x in ssh.upper() for x in ("FAIL", "ERROR", "OFF", "DENIED")):
        out.append(make_alert(
            category="security",
            severity="warning",
            title="SSH Problem",
            description="SSH zeigt einen Fehlerzustand oder ist nicht erreichbar.",
            cause=ssh,
            solution="sshd-Status, Port, Konfiguration und Authentifizierung prüfen.",
            diagnosis=["systemctl status ssh", "ss -tlnp | grep :22", "journalctl -u ssh -n 100 --no-pager", "grep -n '^PermitRootLogin\\|^PasswordAuthentication' /etc/ssh/sshd_config"],
            file_path=["/etc/ssh/sshd_config", "/etc/ssh"],
            log_file=["/var/log/auth.log", "journalctl -u ssh -n 100 --no-pager"],
            recovery_hint="SSH muss wieder sauber erreichbar sein.",
            source="SSH-Check",
            entity=safe_str(snapshot.get("host"), "host"),
            metric="ssh",
            threshold="reachable/ok",
            current_value=ssh,
            summary="SSH Problem",
            extra={"raw": ssh},
        ))

    return out
