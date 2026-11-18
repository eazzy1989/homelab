#!/usr/bin/env python3
from __future__ import annotations

from typing import Any
import subprocess

from guardian_alerts import make_alert


def build_storage_health_alerts(snapshot: dict[str, Any] | None) -> list[dict[str, Any]]:
    snapshot = snapshot or {}
    out=[]

    node=snapshot.get("node","pve")


    # Proxmox Storage API
    for storage in snapshot.get("storages",[]) or []:

        name=str(storage.get("storage","unknown"))
        status=str(storage.get("status","unknown")).lower()

        try:
            percent=float(
                str(storage.get("percent","0"))
                .replace("%","")
            )
        except Exception:
            percent=0


        if status not in ("active", "available", "online"):
            out.append(make_alert(
                category="storage",
                severity="critical",
                title=f"Storage offline: {name}",
                description="Ein Proxmox Storage ist nicht verfügbar.",
                cause=f"Status={status}",
                solution="Storage, Mount und Netzwerk prüfen.",
                diagnosis=[
                    "pvesm status",
                    "cat /etc/pve/storage.cfg",
                    "mount"
                ],
                file_path=[
                    "/etc/pve/storage.cfg"
                ],
                log_file=[
                    "/var/log/syslog"
                ],
                recovery_hint="Storage muss wieder aktiv sein.",
                source="Storage Health",
                entity=name,
                metric="status",
                threshold="active",
                current_value=status,
                summary=f"Storage offline {name}"
            ))


        if percent >= 90:
            severity="critical"
        elif percent >= 80:
            severity="warning"
        else:
            continue


        out.append(make_alert(
            category="storage",
            severity=severity,
            title=f"Storage Auslastung hoch: {name}",
            description="Der Speicherplatz nähert sich dem Limit.",
            cause=f"Belegt: {percent:.1f}%",
            solution="Alte Daten, Backups oder Images prüfen.",
            diagnosis=[
                "pvesm status",
                f"du -sh /mnt/{name}/*"
            ],
            file_path=[
                "/etc/pve/storage.cfg"
            ],
            log_file=[
                "/var/log/syslog"
            ],
            recovery_hint="Freien Speicher schaffen.",
            source="Storage Health",
            entity=name,
            metric="usage",
            threshold="<80%",
            current_value=f"{percent:.1f}%",
            summary=f"Storage voll {name}"
        ))


    # LVM Thin Pool
    try:
        lvs=subprocess.check_output(
            ["lvs","--noheadings","--units","g","-o","lv_name,data_percent,metadata_percent"],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=20,
        )

        for line in lvs.splitlines():

            if "data" not in line:
                continue

            parts=line.split()

            if len(parts)<3:
                continue

            lv,data,meta=parts[:3]

            data=float(data.replace(",",".")) if data!="-" else 0
            meta=float(meta.replace(",",".")) if meta!="-" else 0


            if data >= 90 or meta >= 90:

                out.append(make_alert(
                    category="storage",
                    severity="critical",
                    title="LVM Thin Pool kritisch",
                    description="Der Thin Pool erreicht die kritische Grenze.",
                    cause=f"{lv}: Data={data:.1f}% Meta={meta:.1f}%",
                    solution="Snapshots prüfen und Speicher freigeben.",
                    diagnosis=[
                        "lvs",
                        "pvesm status"
                    ],
                    file_path=[
                        "/etc/lvm"
                    ],
                    log_file=[
                        "/var/log/syslog"
                    ],
                    recovery_hint="Thin Pool muss entlastet werden.",
                    source="LVM Health",
                    entity=node,
                    metric="thinpool",
                    threshold="Data/Meta <90%",
                    current_value=f"{data:.1f}/{meta:.1f}",
                    summary="LVM Thin Pool kritisch"
                ))

    except Exception:
        pass


    return out
