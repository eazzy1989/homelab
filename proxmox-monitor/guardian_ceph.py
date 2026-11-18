#!/usr/bin/env python3
from __future__ import annotations

from typing import Any

from guardian_alerts import make_alert
from guardian_helpers import safe_str


def build_ceph_alerts(snapshot: dict[str, Any] | None) -> list[dict[str, Any]]:
    snapshot = snapshot or {}
    out: list[dict[str, Any]] = []

    ceph = safe_str(snapshot.get("cephstatus") or snapshot.get("ceph") or "")
    if not ceph:
        return out

    up = ceph.upper()
    if any(x in up for x in ("HEALTH_WARN", "HEALTH_ERR", "DEGRADED", "OSD_DOWN", "PG_AVAIL", "PG_DEGRADED")):
        out.append(make_alert(
            category="storage",
            severity="critical",
            title="Ceph problematisch",
            description="Ceph meldet einen kritischen Zustand.",
            cause=ceph,
            solution="Ceph-Status, OSDs, Placement Groups und Netzwerk prüfen.",
            diagnosis=["ceph -s", "ceph health detail", "ceph osd tree", "ceph df"],
            file_path=["/etc/ceph", "/var/lib/ceph"],
            log_file=["/var/log/ceph", "journalctl -u ceph-mon -n 100 --no-pager"],
            recovery_hint="Ceph muss wieder HEALTH_OK sein.",
            source="Ceph-Check",
            entity=safe_str(snapshot.get("host"), "host"),
            metric="health",
            threshold="HEALTH_OK",
            current_value=ceph,
            summary="Ceph problematisch",
            extra={"raw": ceph},
        ))

    return out
