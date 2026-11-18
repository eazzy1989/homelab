#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass, asdict, field
from typing import Any

from guardian_helpers import now_ts, iso_ts, safe_str, stable_hash, ensure_list


# Alert-Historie
# Es werden nur Ereignisse der letzten 7 Tage in der History behalten.
# active/pending Alerts werden davon NICHT betroffen.
HISTORY_RETENTION_SECONDS = 7 * 24 * 60 * 60


# Alert-Entprellung (Sekunden)
ALERT_DELAYS = {
    "vm": 600,
    "vm_status": 600,
    # Container: gleiche Entprellung wie VMs (vorher 0 -> Alarm + falsche
    # Entwarnung im Folgezyklus, auch bei kurzen Neustarts)
    "lxc_status": 600,
    "ct": 600,
    "lxc": 600,

    # Ressourcenalarme erst nach stabiler Überschreitung auslösen
    "vm_resource": 120,
    "lxc_resource": 120,

    "network": 300,
    "internet": 300,
    "dns": 300,
    "api": 300,
    "services": 300,
    # Kategorie-Namen, die die Checks tatsächlich verwenden (vorher ohne
    # Entprellung -> Sofortalarm z. B. beim Start, wenn pveproxy/Node-API
    # noch hochfahren oder bei einem kurzen Dienst-Neustart durch Updates)
    "service": 180,
    "cluster": 300,
    "vm_storage": 120,

    "storage": 180,
    "hardware": 180,
    "kernel": 180,

    "backup": 0,
    "smart": 0,
    "raid": 0,
    "zfs": 0,
    "security": 0,
}


def get_alert_delay(category: str) -> int:
    return ALERT_DELAYS.get(
        safe_str(category).lower(),
        0,
    )



@dataclass
class Alert:
    category: str
    severity: str
    title: str
    description: str
    cause: str
    solution: str
    diagnosis: list[str] = field(default_factory=list)
    file_path: list[str] = field(default_factory=list)
    log_file: list[str] = field(default_factory=list)
    recovery_hint: str = ""
    source: str = ""
    entity: str = ""
    metric: str = ""
    threshold: str = ""
    current_value: str = ""
    first_seen_ts: int = 0
    last_seen_ts: int = 0
    event_ts: int = 0
    status: str = "active"
    alert_hash: str = ""
    summary: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["hash"] = data.pop("alert_hash")
        return data


def make_alert(
    *,
    category: str,
    severity: str,
    title: str,
    description: str,
    cause: str,
    solution: str,
    diagnosis: list[str] | None = None,
    file_path: list[str] | None = None,
    log_file: list[str] | None = None,
    recovery_hint: str = "",
    source: str = "",
    entity: str = "",
    metric: str = "",
    threshold: str = "",
    current_value: str = "",
    summary: str = "",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    event_ts = now_ts()
    alert_hash = stable_hash(category, severity, title, source, entity, metric, threshold)
    obj = Alert(
        category=safe_str(category, "system"),
        severity=safe_str(severity, "warning"),
        title=safe_str(title, "Unbekannter Alarm"),
        description=safe_str(description),
        cause=safe_str(cause),
        solution=safe_str(solution),
        diagnosis=ensure_list(diagnosis),
        file_path=ensure_list(file_path),
        log_file=ensure_list(log_file),
        recovery_hint=safe_str(recovery_hint),
        source=safe_str(source),
        entity=safe_str(entity),
        metric=safe_str(metric),
        threshold=safe_str(threshold),
        current_value=safe_str(current_value),
        first_seen_ts=event_ts,
        last_seen_ts=event_ts,
        event_ts=event_ts,
        status="active",
        alert_hash=alert_hash,
        summary=safe_str(summary),
        extra=extra or {},
    )
    return obj.to_dict()


def _ensure_engine(snapshot: dict[str, Any] | None) -> dict[str, Any]:
    snapshot = snapshot or {}
    engine = snapshot.get("guardian_alert_engine", {}) or {}
    engine.setdefault("active", {})
    engine.setdefault("pending", {})
    engine.setdefault("history", [])
    return engine



def run_guardian_alert_engine(old_snapshot, snapshot, candidates, guardian_context):
    from copy import deepcopy

    old_snapshot = old_snapshot or {}
    snapshot = snapshot or {}
    guardian_context = guardian_context or {}

    engine_raw = guardian_context.get("guardian_alert_engine")
    if not isinstance(engine_raw, dict):
        engine_raw = old_snapshot.get("guardian_alert_engine", {}) or {}
    if not isinstance(engine_raw, dict):
        engine_raw = {}

    active_raw = engine_raw.get("active")
    pending_raw = engine_raw.get("pending")
    history_raw = engine_raw.get("history")

    active = deepcopy(active_raw) if isinstance(active_raw, dict) else {}
    pending = deepcopy(pending_raw) if isinstance(pending_raw, dict) else {}
    history = deepcopy(history_raw) if isinstance(history_raw, list) else []

    now = now_ts()

    def _copy(item):
        return deepcopy(item)

    def _trim_history():
        cutoff = now - HISTORY_RETENTION_SECONDS

        history[:] = [
            item
            for item in history
            if int(item.get("ts", 0) or 0) >= cutoff
        ]

    # Alte History-Einträge bei jedem Guardian-Lauf entfernen.
    # active und pending werden hier ausdrücklich NICHT verändert.
    _trim_history()

    def _record(event, item):
        history.append({
            "ts": now,
            "event": event,
            "hash": safe_str(item.get("hash")),
            "title": safe_str(item.get("title")),
            "severity": safe_str(item.get("severity")),
            "category": safe_str(item.get("category")),
        })
        _trim_history()

    def _normalize(raw):
        if hasattr(raw, "to_dict"):
            raw = raw.to_dict()

        if not isinstance(raw, dict):
            return None

        item = deepcopy(raw)

        h = safe_str(
            item.get("hash")
            or item.get("alert_hash")
            or item.get("id")
        ).strip()
        if not h:
            return None

        category = safe_str(item.get("category")).lower().strip()

        item["hash"] = h
        item["category"] = category
        item["status"] = "pending"
        item["first_seen_ts"] = int(item.get("first_seen_ts") or now)
        item["last_seen_ts"] = now
        item["event_ts"] = int(item.get("event_ts") or now)

        return item

    current = {}
    for raw in candidates or []:
        item = _normalize(raw)
        if not item:
            continue
        current[item["hash"]] = item

    current_hashes = set(current.keys())
    active_hashes = set(active.keys())
    pending_hashes = set(pending.keys())

    for h in list(pending_hashes - current_hashes):
        pending.pop(h, None)

    outgoing = []

    for h in list(active_hashes - current_hashes):
        old_active = active.pop(h, None)
        if not old_active:
            continue

        recovery = _copy(old_active)
        recovery["status"] = "recovery"
        recovery["recovered"] = True
        recovery["recovered_ts"] = now
        recovery["last_seen_ts"] = now
        recovery["event_ts"] = now

        first_seen = int(old_active.get("first_seen_ts") or now)
        recovery["duration_seconds"] = max(0, now - first_seen)

        outgoing.append(recovery)
        _record("recovery", recovery)

    for h, item in current.items():
        delay = int(get_alert_delay(item.get("category", "")))

        if h in active:
            existing = active[h]
            merged = _copy(existing)
            merged.update(item)
            merged["hash"] = h
            merged["status"] = "active"
            merged["first_seen_ts"] = int(existing.get("first_seen_ts") or item.get("first_seen_ts") or now)
            merged["event_ts"] = int(existing.get("event_ts") or now)
            merged["last_seen_ts"] = now
            merged["telegram_sent"] = True
            active[h] = merged
            pending.pop(h, None)
            continue

        if h in pending:
            existing = pending[h]
            merged = _copy(existing)
            merged.update(item)
            merged["hash"] = h
            merged["status"] = "pending"
            merged["first_seen_ts"] = int(existing.get("first_seen_ts") or item.get("first_seen_ts") or now)
            merged["last_seen_ts"] = now
            pending[h] = merged

            age = now - int(merged["first_seen_ts"])
            if delay <= 0 or age >= delay:
                activated = _copy(merged)
                activated["status"] = "active"
                activated["event_ts"] = now
                activated["last_seen_ts"] = now
                activated["telegram_sent"] = False
                active[h] = activated
                pending.pop(h, None)

                outgoing.append(_copy(activated))
                _record("alarm", activated)
            continue

        fresh = _copy(item)
        fresh["hash"] = h
        fresh["status"] = "pending"
        fresh["first_seen_ts"] = now
        fresh["last_seen_ts"] = now

        if delay <= 0:
            activated = _copy(fresh)
            activated["status"] = "active"
            activated["event_ts"] = now
            activated["last_seen_ts"] = now
            activated["telegram_sent"] = False

            active[h] = activated
            outgoing.append(_copy(activated))
            _record("alarm", activated)
        else:
            pending[h] = fresh

    guardian_snapshot = dict(guardian_context)
    guardian_snapshot["guardian_candidates"] = list(current.values())
    guardian_snapshot["guardian_alert_engine"] = {
        "active": active,
        "pending": pending,
        "history": history,
    }
    guardian_snapshot["guardian_alerts_active"] = active
    guardian_snapshot["guardian_alerts_recent"] = history[-20:]
    guardian_snapshot["alerts"] = list(active.values())

    return outgoing, guardian_snapshot

def format_professional_alert(alert: dict[str, Any]) -> str:
    alert = alert or {}
    recovered = bool(alert.get("recovered")) or safe_str(alert.get("status")) == "recovered"
    severity = safe_str(alert.get("severity"), "warning").upper()
    category = safe_str(alert.get("category"), "system")
    title = safe_str(alert.get("title"), "Unbekannter Alarm")
    source = safe_str(alert.get("source"), "-")
    entity = safe_str(alert.get("entity"), "-")
    description = safe_str(alert.get("description"), "-")
    cause = safe_str(alert.get("cause"), "-")
    solution = safe_str(alert.get("solution"), "-")
    threshold = safe_str(alert.get("threshold"), "-")
    current_value = safe_str(alert.get("current_value"), "-")
    metric = safe_str(alert.get("metric"), "-")
    ahash = safe_str(alert.get("hash"), "-")

    if recovered:
        duration = int(alert.get("duration_seconds") or 0)
        lines = [
            f"✅ {title} wieder normal",
            "",
            f"Kategorie: {category}",
            f"Severity: {severity}",
            f"Quelle: {source}",
            f"Entity: {entity}",
            f"Metrik: {metric}",
            f"Dauer: {duration}s",
            f"Recovery: {safe_str(alert.get('recovery_hint'), 'Keine weiteren Maßnahmen notwendig')}",
            f"Zeitpunkt: {iso_ts(alert.get('recovered_ts') or alert.get('recovery_ts'))}",
            f"Beginn: {iso_ts(alert.get('first_seen_ts'))}",
            f"Hash: {ahash}",
            f"Status: RECOVERY",
        ]
        return "\n".join(lines).strip()

    lines = [
        f"🚨 {title}",
        "",
        f"Kategorie: {category}",
        f"Severity: {severity}",
        f"Quelle: {source}",
        f"Entity: {entity}",
        f"Beschreibung: {description}",
        f"Ursache: {cause}",
        f"Aktueller Wert: {current_value}",
        f"Schwellwert: {threshold}",
        f"Lösung: {solution}",
    ]

    diag = ensure_list(alert.get("diagnosis"))
    if diag:
        lines.append("Diagnose:")
        lines.extend(f"- {x}" for x in diag if safe_str(x))

    files = ensure_list(alert.get("file_path"))
    if files:
        lines.append("Dateipfad:")
        lines.extend(f"- {x}" for x in files if safe_str(x))

    logs = ensure_list(alert.get("log_file"))
    if logs:
        lines.append("Logdatei:")
        lines.extend(f"- {x}" for x in logs if safe_str(x))

    lines.extend(
        [
            f"Recovery: {safe_str(alert.get('recovery_hint'), '-')}",
            f"Zeitpunkt: {iso_ts(alert.get('event_ts'))}",
            f"Hash: {ahash}",
            "Status: ALARM",
        ]
    )
    return "\n".join(lines).strip()


def build_hash(*parts: object) -> str:
    return stable_hash(*parts)


def build_all_guardian_alerts(guardian_snapshot: dict[str, Any] | None) -> list[dict[str, Any]]:
    guardian_snapshot = guardian_snapshot or {}
    return list(guardian_snapshot.get("candidates", []) or [])
