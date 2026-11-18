#!/usr/bin/env python3
from __future__ import annotations

from typing import Any

from guardian_alerts import make_alert
from guardian_helpers import safe_str, clamp_float


def build_vm_resource_alerts(snapshot: dict[str,Any] | None) -> list[dict[str,Any]]:
    snapshot = snapshot or {}
    out=[]


    for vm in snapshot.get("qemu",[]) or []:

        vmid=safe_str(vm.get("vmid"))
        name=safe_str(vm.get("name"),f"vm-{vmid}")
        status=safe_str(vm.get("status"),"unknown").lower()

        cpu=clamp_float(vm.get("cpu",0))

        try:
            mem_used=float(
                vm.get("mem_used",
                vm.get("memused",
                vm.get("mem",0))) or 0
            )
        except Exception:
            mem_used=0

        try:
            mem_max=float(
                vm.get("mem_max",
                vm.get("memmax",
                vm.get("maxmem",0))) or 0
            )
        except Exception:
            mem_max=0


        if cpu >= 95:
            out.append(make_alert(
                category="vm_resource",
                severity="critical",
                title=f"VM CPU kritisch: {name}",
                description="Eine VM nutzt dauerhaft sehr viel CPU.",
                cause=f"VMID={vmid}, CPU={cpu:.1f}%",
                solution="Prozesse in der VM prüfen und Last analysieren.",
                diagnosis=[
                    f"qm status {vmid}",
                    f"qm config {vmid}"
                ],
                file_path=[
                    f"/etc/pve/qemu-server/{vmid}.conf"
                ],
                log_file=[
                    "/var/log/syslog"
                ],
                recovery_hint="CPU Nutzung muss sinken.",
                source="VM Resource Check",
                entity=name,
                metric="cpu",
                threshold="<95%",
                current_value=f"{cpu:.1f}%",
                summary=f"VM CPU kritisch {name}"
            ))


        if mem_max > 0:

            # Wenn der QEMU Guest Agent die Gast-RAM-Werte geliefert hat,
            # basiert die RAM-Auslastung auf MemTotal - MemAvailable.
            # Der Proxmox-Wert mem/maxmem ist nur ein Host-seitiger Wert
            # und darf nicht als tatsächliche Gast-RAM-Auslastung bewertet werden.
            mem_source = vm.get("mem_source", "proxmox")

            if mem_source == "guest_agent":
                raw_mem_pct = (mem_used / mem_max) * 100
                mem_pct = min(max(raw_mem_pct, 0.0), 100.0)
            else:
                # Ohne Guest Agent keine falsche Gast-RAM-Warnung erzeugen.
                mem_pct = 0.0

            if mem_pct >= 90:
                severity = "critical" if mem_pct >= 95 else "warning"

                out.append(make_alert(
                    category="vm_resource",
                    severity=severity,
                    title=f"VM RAM hoch: {name}",
                    description="Eine VM verwendet fast den kompletten zugewiesenen RAM.",
                    cause=f"{mem_used/1024/1024/1024:.1f}GB / {mem_max/1024/1024/1024:.1f}GB ({mem_pct:.1f}%)",
                    solution="RAM-Verbrauch prüfen oder VM-RAM erhöhen.",
                    diagnosis=[
                        f"qm config {vmid}",
                        f"qm status {vmid}"
                    ],
                    file_path=[
                        f"/etc/pve/qemu-server/{vmid}.conf"
                    ],
                    log_file=[
                        "/var/log/syslog"
                    ],
                    recovery_hint="RAM Nutzung reduzieren.",
                    source="VM Resource Check",
                    entity=name,
                    metric="ram",
                    threshold="<90%",
                    current_value=f"{mem_pct:.1f}%",
                    summary=f"VM RAM hoch {name}"
                ))


    for ct in snapshot.get("lxc",[]) or []:

        vmid=safe_str(ct.get("vmid"))
        name=safe_str(ct.get("name"),f"lxc-{vmid}")

        try:
            mem_used=float(ct.get("mem_used",0) or 0)
            mem_max=float(ct.get("mem_max",0) or 0)
        except Exception:
            continue

        if mem_max > 0:

            mem_pct=(mem_used/mem_max)*100

            if mem_pct >= 90:
                out.append(make_alert(
                    category="lxc_resource",
                    severity="warning",
                    title=f"LXC RAM hoch: {name}",
                    description="Ein Container verwendet fast den kompletten zugewiesenen RAM.",
                    cause=f"LXCID={vmid}, {mem_used/1024/1024:.0f}MB / {mem_max/1024/1024:.0f}MB ({mem_pct:.1f}%)",
                    solution="RAM-Verbrauch im Container prüfen.",
                    diagnosis=[
                        f"pct status {vmid}",
                        f"pct config {vmid}"
                    ],
                    file_path=[
                        f"/etc/pve/lxc/{vmid}.conf"
                    ],
                    log_file=[
                        "/var/log/syslog"
                    ],
                    recovery_hint="RAM Nutzung reduzieren.",
                    source="LXC Resource Check",
                    entity=name,
                    metric="ram",
                    threshold="<90%",
                    current_value=f"{mem_pct:.1f}%",
                    summary=f"LXC RAM hoch {name}"
                ))

    return out
