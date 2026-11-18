#!/usr/bin/env python3
from __future__ import annotations

from typing import Any
import subprocess
import re

from guardian_alerts import make_alert


CRITICAL_PATTERNS = [
    r"i/o error",
    r"buffer i/o error",
    r"ext4-fs error",
    r"xfs.*error",
    r"nvme.*timeout",
    r"ata.*failed",
    r"oom-killer",
    r"out of memory",
    r"kernel panic",
]

WARNING_PATTERNS = [
    r"link is down",
    r"hung task",
    r"blocked for more than",
]


IGNORE_PATTERNS = [
    r"sgx disabled",
    r"taints kernel",
    r"aspm",
    r"ima",
    r"regulatory.db",
]


def build_log_alerts(snapshot: dict[str,Any] | None) -> list[dict[str,Any]]:
    out=[]

    try:
        logs=subprocess.check_output(
            [
                "journalctl",
                "-k",
                "--since",
                "15 minutes ago",
                "--no-pager"
            ],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=20,
        )

    except Exception:
        return out


    findings=[]

    lines = logs.splitlines()

    # Link-Flaps nur dann als aktiven Warning werten,
    # wenn der betreffende Netzwerk-Link am Ende des
    # überwachten Zeitfensters weiterhin DOWN ist.
    link_state = {}

    for line in lines:
        low = line.lower()

        match = re.search(
            r'(?P<iface>\\b(?:enp|eno|ens|eth)[0-9]+(?:s[0-9]+)?(?:f[0-9]+)?)\\b.*link is (?P<state>down|up)',
            low
        )

        if match:
            link_state[match.group("iface")] = match.group("state")

    for line in lines:

        low=line.lower()

        if any(re.search(x,low) for x in IGNORE_PATTERNS):
            continue

        # Ein Link-Is-Down zählt nur, wenn der betreffende
        # Link aktuell nicht wieder UP ist.
        if "link is down" in low:
            match = re.search(
                r'(?P<iface>\\b(?:enp|eno|ens|eth)[0-9]+(?:s[0-9]+)?(?:f[0-9]+)?)\\b.*link is down',
                low
            )

            if match:
                iface = match.group("iface")
                if link_state.get(iface) == "up":
                    continue

        if any(re.search(x,low) for x in CRITICAL_PATTERNS):
            findings.append(("critical",line))

        elif any(re.search(x,low) for x in WARNING_PATTERNS) and "link is down" not in low:
            findings.append(("warning",line))


    if findings:

        severity="critical" if any(
            x[0]=="critical" for x in findings
        ) else "warning"


        out.append(make_alert(
            category="kernel",
            severity=severity,
            title="Kernel Fehler erkannt",
            description="Das Systemjournal enthält kritische Kernel-Meldungen.",
            cause="\n".join(
                x[1] for x in findings[:10]
            ),
            solution="Kernel, Hardware und Storage prüfen.",
            diagnosis=[
                "journalctl -k -p warning",
                "dmesg -T",
                "smartctl -a /dev/sdX"
            ],
            file_path=[
                "/var/log",
            ],
            log_file=[
                "journalctl -k"
            ],
            recovery_hint="Fehlerquelle beheben und Logs weiter beobachten.",
            source="Kernel Log Check",
            entity="host",
            metric="kernel_errors",
            threshold="0 critical errors",
            current_value=str(len(findings)),
            summary="Kernel Fehler erkannt",
        ))

    return out
