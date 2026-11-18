#!/usr/bin/env python3
"""WAN-, Geräte- und Provider-Ansichten für den Proxmox Guardian.

Ersetzt die bisherigen format_wan_*-Funktionen in monitor.py. Korrekturen:

* events.csv hat seit WAN-Monitor V2 13 Spalten (+ TCP/443). Der alte Leser
  akzeptierte nur exakt 11 -> alle Ereignisse wurden verworfen, die Ansichten
  zeigten immer "Keine Ereignisse". Jetzt: >= 11 Spalten, kein Header nötig.
* Echte Ausfälle (INTERNET, LAN_GATEWAY) werden von Kurzstörungen getrennt
  (ICMP_ONLY = einzelne Ping-Verluste, APP_ONLY = einzelner DNS/HTTPS-Fehler).
* Gerät: tatsächlicher Dienststatus statt fest "Überwachung aktiv".
* Provider: überlappende Einträge (Live-Monitor + Router-Log) werden
  zusammengeführt; Hinweis, wenn der Router-Import nicht mehr läuft.
* Live-Pings parallel statt nacheinander (bis zu 5 s schneller).
"""
from __future__ import annotations

import csv
import os
import html
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path

from utils import ping_target

WAN_EVENTS = Path("/var/log/proxmox-wan-monitor/events.csv")
WAN_MEASUREMENTS = Path("/var/log/proxmox-wan-monitor/measurements.csv")
DEVICE_EVENTS = Path("/var/lib/proxmox-wan-monitor/device-events.csv")
DEVICE_LOG = Path("/var/log/proxmox-wan-monitor/device.log")
CABLE_EVENTS = Path("/var/lib/proxmox-wan-monitor/router-cable-events.csv")
CABLE_IMPORT_LOG = Path("/var/log/proxmox-wan-monitor/router-event-import.log")
CABLE_CSV = Path("/var/lib/proxmox-wan-monitor/router-cable.csv")

GATEWAY = os.getenv("ROUTER_IP", "192.168.1.1")
TARGETS = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "1.0.0.1"]

CONFIRMED_TYPES = {"INTERNET", "LAN_GATEWAY"}
TYPE_TEXT = {
    "INTERNET": "Internet-Ausfall",
    "LAN_GATEWAY": "Router/LAN nicht erreichbar",
    "ICMP_ONLY": "Ping-Verluste (kein Ausfall)",
    "APP_ONLY": "DNS/HTTPS-Fehler (kein Ausfall)",
    # ältere Typen aus V1
    "ICMP_INTERNET": "ICMP-Internetstörung",
    "PARTIAL_INTERNET": "Teilweiser Internet-Ausfall",
    "DNS_HTTPS": "DNS-/HTTPS-Störung",
}
SEP = "────────────────────────────────"


# ------------------------------------------------------------------ Helfer

def _esc(value) -> str:
    return html.escape(str(value), quote=False)


def fmt_duration(seconds: float) -> str:
    seconds = max(0.0, float(seconds or 0))
    if seconds < 60:
        return f"{seconds:.1f} s".replace(".", ",")
    total = int(round(seconds))
    hours, rem = divmod(total, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours} Std. {minutes} Min."
    return f"{minutes} Min. {secs} Sek."


def fmt_short(seconds: float) -> str:
    """Kompakt für Tabellen: 36,9s · 2:35 · 1:02:10"""
    seconds = max(0.0, float(seconds or 0))
    if seconds < 60:
        return f"{seconds:.1f}s".replace(".", ",")
    total = int(round(seconds))
    hours, rem = divmod(total, 3600)
    minutes, secs = divmod(rem, 60)
    return f"{hours}:{minutes:02d}:{secs:02d}" if hours else f"{minutes}:{secs:02d}"


def _parse_dt(text: str) -> datetime | None:
    text = str(text or "").strip().replace("T", " ")
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    # Zeitzonen entfernen -> lokale, naive Zeit (wie die übrigen Dateien)
    if dt.tzinfo is not None:
        dt = dt.astimezone().replace(tzinfo=None)
    return dt


def _service_state(unit: str) -> str:
    try:
        r = subprocess.run(["systemctl", "is-active", unit], capture_output=True, text=True, timeout=5)
        return (r.stdout or "").strip() or "unknown"
    except Exception:
        return "unknown"


def _age_text(path: Path) -> tuple[float | None, str]:
    try:
        age = time.time() - path.stat().st_mtime
    except OSError:
        return None, "keine Daten"
    if age < 90:
        return age, "gerade eben"
    if age < 3600:
        return age, f"vor {int(age // 60)} Min."
    if age < 86400:
        return age, f"vor {int(age // 3600)} Std."
    return age, f"vor {int(age // 86400)} Tagen"


def _icon(ok) -> str:
    return "🟢" if str(ok).strip().lower() in {"1", "true", "up", "ok"} else "🔴"


MONTHS_SHORT = ["Jan.", "Feb.", "März", "Apr.", "Mai", "Juni", "Juli", "Aug.", "Sep.", "Okt.", "Nov.", "Dez."]


def _month_label(year: int, month: int) -> str:
    return f"{MONTHS_SHORT[month - 1]} {year}"


def _monthly_summary(items: list[dict], exclude_current: bool = True) -> list[str]:
    """Eine Zeile je Monat: Anzahl und Gesamtdauer (neueste zuerst)."""
    now = datetime.now()
    buckets: dict[tuple[int, int], list[float]] = {}
    for it in items:
        key = (it["start"].year, it["start"].month)
        if exclude_current and key == (now.year, now.month):
            continue
        buckets.setdefault(key, []).append(it["duration"])
    return [
        f"• {_month_label(y, m)}: {len(d)} · {fmt_duration(sum(d))}"
        for (y, m), d in sorted(buckets.items(), reverse=True)
    ]


# ------------------------------------------------------------------ WAN-Ereignisse

def read_wan_events(path: Path | None = None) -> list[dict]:
    path = path or WAN_EVENTS
    events: list[dict] = []
    try:
        with path.open("r", encoding="utf-8", newline="") as fh:
            for row in csv.reader(fh):
                if len(row) < 11 or not row[0][:1].isdigit():
                    continue  # Header, Leerzeilen, defekte Zeilen
                start, end = _parse_dt(row[0]), _parse_dt(row[1])
                if start is None or end is None:
                    continue
                try:
                    duration = float(row[2])
                except ValueError:
                    duration = max(0.0, (end - start).total_seconds())
                events.append({
                    "start": start, "end": end, "duration": duration, "type": row[3].strip(),
                    "gateway": row[4], "t1": row[5], "t2": row[6], "t3": row[7], "t4": row[8],
                    "dns": row[9], "https": row[10],
                    "tcp1": row[11] if len(row) > 11 else "",
                    "tcp2": row[12] if len(row) > 12 else "",
                })
    except OSError:
        pass
    events.sort(key=lambda e: e["start"])
    return events


def _is_confirmed(event: dict) -> bool:
    return event["type"] in CONFIRMED_TYPES


def _day_summary(events: list[dict], day) -> dict:
    day_events = [e for e in events if e["start"].date() == day]
    confirmed = [e for e in day_events if _is_confirmed(e)]
    internet = [e for e in confirmed if e["type"] == "INTERNET"]
    return {
        "internet": len(internet),
        "lan": len(confirmed) - len(internet),
        "downtime": sum(e["duration"] for e in confirmed),
        "longest": max((e["duration"] for e in confirmed), default=0.0),
        "noise": len(day_events) - len(confirmed),
    }


def _live_check() -> dict:
    hosts = [GATEWAY] + TARGETS
    with ThreadPoolExecutor(max_workers=len(hosts)) as pool:
        results = dict(zip(hosts, pool.map(ping_target, hosts)))
    return results


def _latency(result: dict) -> str:
    value = (result or {}).get("latency_ms")
    return f"{value:.1f} ms" if isinstance(value, (int, float)) else "keine Antwort"


def _event_line(event: dict) -> str:
    s = event["start"].strftime("%d.%m. %H:%M:%S")
    return f"• {s} · {fmt_duration(event['duration'])} · {TYPE_TEXT.get(event['type'], event['type'])}"


def format_wan_monitor(snapshot=None) -> str:
    events = read_wan_events()
    live = _live_check()
    gw_ok = bool(live[GATEWAY].get("ok"))
    ok_count = sum(1 for t in TARGETS if live[t].get("ok"))

    if not gw_ok:
        status = "🔴 Router / LAN nicht erreichbar"
    elif ok_count == len(TARGETS):
        status = "🟢 Online"
    elif ok_count == 0:
        status = "🔴 Internet nicht erreichbar"
    else:
        status = f"🟡 {ok_count}/{len(TARGETS)} Internetziele erreichbar"

    svc = _service_state("proxmox-wan-monitor.service")
    _, fresh = _age_text(WAN_MEASUREMENTS)
    monitor_line = (
        f"🟢 Messung läuft (letzter Wert {fresh})" if svc == "active"
        else f"🔴 WAN-Monitor-Dienst: {svc}"
    )

    today = _day_summary(events, datetime.now().date())
    lines = [
        "📡 WAN-Monitor", SEP, "",
        f"Status: {status}",
        monitor_line,
        "",
        "📡 LIVE",
        f"• Router  {_icon(gw_ok)} {_latency(live[GATEWAY])}",
    ]
    for t in TARGETS:
        lines.append(f"• {t:<9}  {_icon(live[t].get('ok'))} {_latency(live[t])}")

    lines += [
        "",
        "📊 HEUTE",
        f"• Internet-Ausfälle: {today['internet']}",
        f"• Router/LAN-Ausfälle: {today['lan']}",
        f"• Ausfallzeit gesamt: {fmt_duration(today['downtime'])}",
        f"• Längster Ausfall: {fmt_duration(today['longest'])}",
        f"• Kurzstörungen (nicht gewertet): {today['noise']}",
        "",
        "📜 LETZTE AUSFÄLLE",
    ]
    confirmed = [e for e in events if _is_confirmed(e)]
    if confirmed:
        lines += [_event_line(e) for e in reversed(confirmed[-5:])]
    else:
        lines.append("• Keine Ausfälle aufgezeichnet.")

    lines += [
        "",
        "ℹ️ Messung jede Sekunde: Router, 4 Internetziele,",
        "   TCP/443, DNS und HTTPS.",
        "ℹ️ Ausfall = mind. 3 von 4 Zielen, TCP und HTTPS",
        "   gleichzeitig weg. Einzelne Ping-Verluste zählen nicht.",
    ]
    return "\n".join(lines)


def format_wan_logs(snapshot=None, limit: int = 12, noise_min_seconds: float = 2.0) -> str:
    events = read_wan_events()
    shown = [e for e in events if _is_confirmed(e) or e["duration"] >= noise_min_seconds]
    hidden = len(events) - len(shown)

    lines = ["📜 WAN-Logs", SEP, ""]
    if not shown:
        lines.append("Keine relevanten Ereignisse aufgezeichnet.")
    for event in reversed(shown[-limit:]):
        icons = (
            f"GW{_icon(event['gateway'])} "
            + " ".join(f"{t.split('.')[0]}{_icon(event[k])}" for t, k in zip(TARGETS, ("t1", "t2", "t3", "t4")))
            + f" DNS{_icon(event['dns'])} HTTPS{_icon(event['https'])}"
        )
        if event["tcp1"] != "":
            icons += f" TCP{_icon(event['tcp1'])}{_icon(event['tcp2'])}"
        lines += [
            _event_line(event),
            f"  {icons}",
            "",
        ]
    if hidden:
        lines.append(f"ℹ️ {hidden} Kurzstörung(en) unter {noise_min_seconds:.0f} s ausgeblendet.")
    lines += [
        "ℹ️ GW = Router, 1/8/9 = Internetziele 1.1.1.1,",
        "   8.8.8.8, 9.9.9.9, 1.0.0.1 (in dieser Reihenfolge)",
        "ℹ️ Rohdaten: /var/log/proxmox-wan-monitor/events.csv",
    ]
    return "\n".join(lines).strip()


def format_wan_stats(snapshot=None, days: int = 7) -> str:
    events = read_wan_events()
    today = datetime.now().date()
    rows = []
    totals = {"internet": 0, "lan": 0, "downtime": 0.0, "noise": 0}
    for offset in range(days):
        day = today - timedelta(days=offset)
        s = _day_summary(events, day)
        for k in totals:
            totals[k] += s[k]
        rows.append(
            f"{day.strftime('%d.%m.'):<7}{s['internet']:>5}{s['lan']:>5}"
            f"{fmt_short(s['downtime']):>9}{fmt_short(s['longest']):>8}{s['noise']:>6}"
        )
    first = events[0]["start"].strftime("%d.%m.%Y") if events else "–"
    table = "\n".join([
        f"{'Tag':<7}{'Ausf':>5}{'Box':>5}{'Dauer':>9}{'max':>8}{'Kurz':>6}",
        *rows,
        "-" * 40,
        f"{'Summe':<7}{totals['internet']:>5}{totals['lan']:>5}{fmt_short(totals['downtime']):>9}{'':>8}{totals['noise']:>6}",
    ])
    return "\n".join([
        "📊 WAN-Statistik (7 Tage)", SEP, "",
        f"<pre>{_esc(table)}</pre>",
        "",
        "Ausf = Internet-Ausfälle",
        "Box = Router nicht erreichbar (z. B. Neustart)",
        "Dauer = Ausfallzeit gesamt (Min:Sek)",
        "max = längster Ausfall",
        "Kurz = einzelne Ping-Verluste (nicht gewertet)",
        f"ℹ️ Daten vorhanden ab {first}",
    ])


# ------------------------------------------------------------------ DEVICE

def format_device_report(snapshot=None, limit: int = 10, min_seconds: float = 2.0) -> str:
    svc = _service_state("proxmox-device-monitor.service")
    _, last_seen = _age_text(DEVICE_LOG)
    rows = []
    try:
        with DEVICE_EVENTS.open("r", encoding="utf-8", newline="") as fh:
            for row in csv.DictReader(fh):
                start, end = _parse_dt(row.get("start")), _parse_dt(row.get("end"))
                if start is None or end is None:
                    continue
                try:
                    duration = float(row.get("duration_seconds") or 0)
                except ValueError:
                    duration = (end - start).total_seconds()
                rows.append({"start": start, "end": end, "duration": duration,
                             "class": row.get("classification", "")})
    except OSError:
        pass
    rows.sort(key=lambda r: r["start"])
    relevant = [r for r in rows if r["duration"] >= min_seconds]
    week_ago = datetime.now() - timedelta(days=7)
    last7 = [r for r in relevant if r["start"] >= week_ago]

    if svc == "active":
        status = f"🟢 Überwachung aktiv (letzte Aktivität {last_seen})"
    else:
        status = f"🔴 Überwachung NICHT aktiv (Dienst: {svc}, letzte Aktivität {last_seen})"

    cause_text = {
        "DEVICE_UNREACHABLE_ONLY": "nur das überwachte Gerät betroffen (WLAN)",
        "DEVICE_UNREACHABLE_INTERNET_UNREACHABLE": "zeitgleich Internet weg",
        "DEVICE_UNREACHABLE_GW_UNREACHABLE": "zeitgleich Router weg",
    }
    lines = [
        "📶 Geräte-Verbindungen", SEP, "",
        status,
        "",
        f"• Letzte 7 Tage: {len(last7)}",
    ]
    now = datetime.now()
    this_month = [r for r in relevant if (r["start"].year, r["start"].month) == (now.year, now.month)]
    lines += ["", f"📅 {_month_label(now.year, now.month).upper()}: {len(this_month)} Abbruch/Abbrüche"]
    if not this_month:
        lines.append("• Keine Abbrüche in diesem Monat.")
    for r in reversed(this_month[-limit:]):
        lines.append(
            f"• {r['start'].strftime('%d.%m. %H:%M:%S')} · {fmt_duration(r['duration'])} · "
            f"{cause_text.get(r['class'], r['class'] or '–')}"
        )
    if len(this_month) > limit:
        lines.append(f"• … und {len(this_month) - limit} weitere")
    history = _monthly_summary(relevant)
    if history:
        lines += ["", "🗂 FRÜHERE MONATE (Anzahl · Dauer)"] + history
    hidden = len(rows) - len(relevant)
    if hidden:
        lines += ["", f"ℹ️ {hidden} Aussetzer unter {min_seconds:.0f} s ausgeblendet."]
    return "\n".join(lines)


# ------------------------------------------------------------------ Provider

def read_cable_events(path: Path | None = None) -> list[dict]:
    """Kabelabbrüche aus Live-Monitor (DOWN) und Router-Log (ROUTER_KABEL).
    Überlappende/nahe Einträge desselben Ausfalls werden zusammengeführt;
    der Router-Eintrag hat Vorrang (offizielle Quelle)."""
    path = path or CABLE_EVENTS
    raw = []
    try:
        with path.open("r", encoding="utf-8", newline="") as fh:
            for row in csv.DictReader(fh):
                status = str(row.get("status", "")).strip()
                if status not in ("DOWN", "ROUTER_KABEL"):
                    continue
                start, end = _parse_dt(row.get("start")), _parse_dt(row.get("end"))
                if start is None or end is None:
                    continue
                raw.append({"start": start, "end": end,
                            "duration": max(0.0, (end - start).total_seconds()),
                            "source": status})
    except OSError:
        return []
    raw.sort(key=lambda e: e["start"])
    merged: list[dict] = []
    for ev in raw:
        if merged:
            last = merged[-1]
            close = abs((ev["start"] - last["start"]).total_seconds()) <= 60
            overlap = ev["start"] <= last["end"] + timedelta(seconds=5)
            if close or overlap:
                if ev["source"] == "ROUTER_KABEL" and last["source"] != "ROUTER_KABEL":
                    merged[-1] = ev
                elif ev["source"] == last["source"]:
                    last["end"] = max(last["end"], ev["end"])
                    last["duration"] = (last["end"] - last["start"]).total_seconds()
                continue
        merged.append(dict(ev))
    # Neu-Synchronisation direkt nach einem Router-Neustart (z. B.
    # Firmware-Update) ist keine Störung des Netzbetreibers.
    restarts = [
        (e["start"] - timedelta(seconds=60), e["end"] + timedelta(minutes=10))
        for e in read_wan_events() if e["type"] == "LAN_GATEWAY"
    ]
    return [m for m in merged if not any(a <= m["start"] <= b for a, b in restarts)]


def format_wan_report(snapshot=None, limit: int = 25) -> str:
    events = read_cable_events()
    now = datetime.now()
    last30 = [e for e in events if e["start"] >= now - timedelta(days=30)]

    lines = ["📄 Provider-Störungen", SEP, "", "Quelle: Router-Kabelstatus"]

    age, age_text = _age_text(CABLE_IMPORT_LOG)
    if age is None or age > 3 * 3600:
        lines.append(f"⚠️ Router-Ereignisimport zuletzt {age_text}")
    cable_svc = _service_state("proxmox-router-cable-monitor.service")
    if cable_svc != "active":
        lines.append(f"⚠️ Kabelmonitor-Dienst: {cable_svc}")

    # Internet-Ausfälle laut WAN-Messung (Kabel synchron, Internet trotzdem weg)
    wan_out = [e for e in read_wan_events() if e["type"] == "INTERNET" and e["start"] >= now - timedelta(days=30)]
    wan_lines = []
    if wan_out:
        def _during_cable(w):
            return any(c["start"] - timedelta(seconds=30) <= w["start"] <= c["end"] + timedelta(seconds=30) for c in events)
        synced = sum(1 for w in wan_out if not _during_cable(w))
        wan_lines = [
            "",
            "🌐 Internet-Ausfälle laut WAN-Messung (30 Tage)",
            f"• {len(wan_out)} Ausfälle · Ausfallzeit {fmt_duration(sum(e['duration'] for e in wan_out))}"
            f" · längster {fmt_duration(max(e['duration'] for e in wan_out))}",
            f"• Davon {synced} bei synchronem Kabel und erreichbarer",
            "  Router – die Störung lag also außerhalb",
            "  deines Heimnetzes.",
            "• Details: 📜 WAN-Logs und 📊 Statistik",
        ]

    if not events:
        lines += ["", "Keine Kabelabbrüche aufgezeichnet."] + wan_lines
        return "\n".join(lines)

    lines += [
        "",
        f"🔴 Kabelabbrüche gesamt: {len(events)} (seit {events[0]['start'].strftime('%d.%m.%Y')})",
        f"• Letzte 30 Tage: {len(last30)} · Ausfallzeit {fmt_duration(sum(e['duration'] for e in last30))}",
        f"• Längster Abbruch: {fmt_duration(max(e['duration'] for e in events))}",
    ]

    this_month = [e for e in events if (e["start"].year, e["start"].month) == (now.year, now.month)]
    lines += ["", f"📅 KABELABBRÜCHE {_month_label(now.year, now.month).upper()}: {len(this_month)}"]
    if not this_month:
        lines.append("• Keine Kabelabbrüche in diesem Monat.")
    for ev in list(reversed(this_month))[:limit]:
        lines.append(
            f"• {ev['start'].strftime('%d.%m. %H:%M:%S')} → {ev['end'].strftime('%H:%M:%S')}  {fmt_duration(ev['duration'])}"
        )
    lines += wan_lines
    history = _monthly_summary(events)
    if history:
        lines += ["", "🗂 FRÜHERE MONATE – Kabelabbrüche (Anzahl · Dauer)"] + history
    lines += [
        "",
        "📨 Ausführliches Störungsprotokoll für Provider:",
        "   Button „Monatsbericht“ – kommt als Datei.",
    ]
    lines += [
        "",
        "ℹ️ Kabelabbruch = Synchronisationsverlust des",
        "   Kabelanschlusses laut Router.",
    ]
    return "\n".join(lines)
