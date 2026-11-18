#!/usr/bin/env python3
from __future__ import annotations

from typing import Any
import subprocess
import re
from collections import Counter

from guardian_alerts import make_alert


def build_ssh_security_alerts(snapshot: dict[str,Any] | None) -> list[dict[str,Any]]:
    out=[]

    try:
        logs=subprocess.check_output(
            [
                "journalctl",
                "-u",
                "sshd",
                "--since",
                "5 minutes ago",
                "--no-pager"
            ],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=20,
        )
    except Exception:
        return out


    failed=[]

    for line in logs.splitlines():

        if any(x in line.lower() for x in [
            "failed password",
            "authentication failure",
            "invalid user",
            "too many authentication failures"
        ]):
            failed.append(line)


    if len(failed) >= 10:

        ips=[]

        for line in failed:
            m=re.search(
                r"from ([0-9a-fA-F\.:]+)",
                line
            )
            if m:
                ips.append(m.group(1))


        top_ip=Counter(ips).most_common(1)


        out.append(make_alert(
            category="security",
            severity="warning",
            title="SSH Loginversuche auffällig",
            description="Viele fehlgeschlagene SSH Authentifizierungen erkannt.",
            cause=(
                f"{len(failed)} Fehlversuche in 5 Minuten.\n"
                f"Häufigste Quelle: {top_ip[0][0] if top_ip else 'unbekannt'}"
            ),
            solution="SSH Logs prüfen und Quelle kontrollieren.",
            diagnosis=[
                "journalctl -u sshd --since '10 minutes ago'",
                "last",
                "ss -tnp | grep ssh"
            ],
            file_path=[
                "/etc/ssh/sshd_config"
            ],
            log_file=[
                "journalctl -u sshd"
            ],
            recovery_hint="Keine weiteren Maßnahmen wenn legitimer Zugriff.",
            source="SSH Security Check",
            entity="sshd",
            metric="failed_logins",
            threshold="<10/5min",
            current_value=str(len(failed)),
            summary="SSH Loginversuche auffällig",
        ))

    return out
