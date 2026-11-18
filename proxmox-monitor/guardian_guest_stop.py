#!/usr/bin/env python3
"""Gemeinsame Erkennung "VM/Container unerwartet gestoppt".

Vorher:
* VM: Der Kandidat existierte nur in dem einen Zyklus des Statuswechsels.
  Mit 600 s Entprellung (ALERT_DELAYS["vm_status"]) wurde er nie aktiv
  -> der Alarm konnte technisch nie ausgelöst werden.
* LXC: ohne Entprellung -> sofortiger Alarm, im nächsten Zyklus eine
  falsche "wieder normal"-Meldung, obwohl der Container weiter gestoppt war.
* Beide: auch absichtliche Stopps (GUI/CLI) wurden als "unerwartet" gemeldet.

Jetzt:
* Kandidat bleibt bestehen, solange der Gast gestoppt ist und der Alarm
  bereits pending/aktiv ist -> Entprellung funktioniert, Recovery erst beim
  tatsächlichen Wiederanlauf.
* Absichtliche Stopps (Proxmox-Task stop/shutdown/destroy/migrate für diese
  ID in der letzten Stunde) werden nicht gemeldet.
"""
from __future__ import annotations

import time
from typing import Any, Callable

from guardian_helpers import safe_str

INTENT_WINDOW_SECONDS = 3600

INTENT_TASKS = {
    "qemu": {"qmstop", "qmshutdown", "qmdestroy", "qmigrate", "qmsuspend", "qmpause", "qmreboot"},
    "lxc": {"vzstop", "vzshutdown", "vzdestroy", "vzmigrate", "vzsuspend", "vzreboot"},
}


def _engine_hashes(old_snapshot: dict[str, Any]) -> set[str]:
    engine = (old_snapshot or {}).get("guardian_alert_engine", {}) or {}
    hashes: set[str] = set()
    for bucket in ("active", "pending"):
        data = engine.get(bucket, {}) or {}
        if isinstance(data, dict):
            hashes.update(str(h) for h in data.keys())
    return hashes


def _intentional_stop(kind: str, vmid: str, *snapshots: dict[str, Any]) -> bool:
    now = time.time()
    types = INTENT_TASKS.get(kind, set())
    for snap in snapshots:
        for task in (snap or {}).get("tasks", []) or []:
            try:
                if str(task.get("type", "")).lower() not in types:
                    continue
                if safe_str(task.get("id")) != vmid:
                    continue
                if now - float(task.get("starttime", 0) or 0) <= INTENT_WINDOW_SECONDS:
                    return True
            except Exception:
                continue
    return False


def build_guest_stop_alerts(
    kind: str,
    old_snapshot: dict[str, Any] | None,
    snapshot: dict[str, Any] | None,
    make_candidate: Callable[[str, str, str, str], dict[str, Any]],
) -> list[dict[str, Any]]:
    """kind: "qemu" oder "lxc". make_candidate(vmid, name, old_status, new_status) -> Alert-Dict."""
    old_snapshot = old_snapshot or {}
    snapshot = snapshot or {}
    out: list[dict[str, Any]] = []

    old_guests = {safe_str(x.get("vmid")): x for x in old_snapshot.get(kind, []) or []}
    known = _engine_hashes(old_snapshot)

    for guest in snapshot.get(kind, []) or []:
        vmid = safe_str(guest.get("vmid"))
        name = safe_str(guest.get("name"), f"{'vm' if kind == 'qemu' else 'ct'}-{vmid}")
        new_status = safe_str(guest.get("status"), "").lower()
        if new_status != "stopped":
            continue

        old = old_guests.get(vmid)
        old_status = safe_str((old or {}).get("status"), "").lower()

        candidate = make_candidate(vmid, name, old_status or "running", new_status)
        transition = old_status == "running"
        ongoing = candidate.get("hash") in known

        if not (transition or ongoing):
            continue
        if _intentional_stop(kind, vmid, snapshot, old_snapshot):
            continue
        out.append(candidate)

    return out
