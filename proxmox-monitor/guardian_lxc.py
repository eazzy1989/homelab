#!/usr/bin/env python3
from __future__ import annotations

from typing import Any

from guardian_alerts import make_alert
from guardian_helpers import safe_str


def build_lxc_alerts(
    snapshot: dict[str, Any] | None
) -> list[dict[str, Any]]:

    snapshot = snapshot or {}
    out=[]

    for ct in snapshot.get("lxc",[]) or []:

        vmid=safe_str(ct.get("vmid"))
        name=safe_str(ct.get("name"),f"ct-{vmid}")

        cpu=float(ct.get("cpu",0) or 0)

        mem_used=float(
            ct.get("mem_used",0) or 0
        )

        mem_max=float(
            ct.get("mem_max",0) or 0
        )


        if cpu >= 95:
            out.append(make_alert(
                category="lxc",
                severity="critical",
                title=f"LXC CPU kritisch: {name}",
                description="Ein Container nutzt extrem viel CPU.",
                cause=f"CPU {cpu:.1f}%",
                solution="Prozesse im Container prüfen.",
                diagnosis=[
                    f"pct status {vmid}",
                    f"pct exec {vmid} -- top"
                ],
                file_path=[
                    f"/etc/pve/lxc/{vmid}.conf"
                ],
                log_file=[
                    "/var/log/syslog"
                ],
                recovery_hint="CPU-Auslastung muss sinken.",
                source="LXC Resource Check",
                entity=name,
                metric="cpu",
                threshold="<95%",
                current_value=f"{cpu:.1f}%",
                summary=f"LXC CPU kritisch {name}"
            ))


        if mem_max > 0:

            mem_pct=(mem_used/mem_max)*100

            if mem_pct >= 90:

                out.append(make_alert(
                    category="lxc",
                    severity="warning",
                    title=f"LXC RAM hoch: {name}",
                    description="Container ist fast am RAM-Limit.",
                    cause=f"{mem_used/1024/1024:.0f}MB / {mem_max/1024/1024:.0f}MB ({mem_pct:.1f}%)",
                    solution="RAM-Limit oder Prozesse prüfen.",
                    diagnosis=[
                        f"pct status {vmid}",
                        f"pct exec {vmid} -- free -h"
                    ],
                    file_path=[
                        f"/etc/pve/lxc/{vmid}.conf"
                    ],
                    log_file=[
                        "/var/log/syslog"
                    ],
                    recovery_hint="RAM-Verbrauch reduzieren.",
                    source="LXC Resource Check",
                    entity=name,
                    metric="memory",
                    threshold="<90%",
                    current_value=f"{mem_pct:.1f}%",
                    summary=f"LXC RAM hoch {name}"
                ))


    return out
