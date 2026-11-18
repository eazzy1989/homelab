from datetime import datetime
"""
Notifications module.

Wird schrittweise aus monitor.py befüllt.
"""

__all__ = []

def _alert_category_meta(category: str):
    mapping = {
        "network": ("🌐", "Netzwerk"),
        "dns": ("🌐", "Netzwerk"),
        "telegram": ("🌐", "Netzwerk"),
        "internet": ("🌐", "Netzwerk"),
        "hardware": ("🌡", "Hardware"),
        "backup": ("📦", "Backup"),
        "disk": ("💿", "Laufwerke"),
        "storage": ("💿", "Laufwerke"),
        "smart": ("💿", "Laufwerke"),
        "zfs": ("💿", "Laufwerke"),
        "raid": ("💿", "Laufwerke"),
        "qemu": ("🖥", "QEMU"),
        "lxc": ("📦", "LXC"),
        "updates": ("🧩", "Updates"),
        "system": ("🚨", "System"),
    }
    return mapping.get(category, ("🚨", "System"))

def _alert_key(alert):
    if not isinstance(alert, dict):
        return str(alert)
    if alert.get("key"):
        return str(alert.get("key"))
    return "|".join([
        str(alert.get("category", "")),
        str(alert.get("severity", "")),
        str(alert.get("title", "")),
        str(alert.get("source", "")),
    ])


def _alert_text(alert):
    if not isinstance(alert, dict):
        return str(alert)
    icon, label = _alert_category_meta(alert.get("category", "system"))
    sev = str(alert.get("severity", "warning"))
    prefix = "🟢" if alert.get("recovered") else ("🔴" if sev == "critical" else "🟡" if sev == "warning" else "🔵")
    title = str(alert.get("title", "")).strip()
    details = str(alert.get("details", "")).strip()
    source = str(alert.get("source", "")).strip()
    time_text = str(alert.get("time", "")).strip()
    lines = [f"{prefix} {icon} {label}: {title}"]
    if details:
        lines.append(details)
    if source:
        lines.append(f"Quelle: {source}")
    if time_text:
        lines.append(time_text)
    return "\\n".join(lines)

def _alert_time(snapshot=None):
    try:
        if isinstance(snapshot, dict) and snapshot.get("last_check"):
            s = str(snapshot.get("last_check")).strip()
            if "•" in s:
                return s.split("•")[-1].strip()
            parts = s.split()
            if parts:
                return parts[-1]
        return datetime.now().strftime("%H:%M")
    except Exception:
        return datetime.now().strftime("%H:%M")

def _make_alert(severity, category, title, details="", source="", time_text="", recovered=False, key=""):
    return {
        "severity": str(severity or "warning"),
        "category": str(category or "system"),
        "title": str(title or "").strip(),
        "details": str(details or "").strip(),
        "source": str(source or "").strip(),
        "time": str(time_text or datetime.now().strftime("%H:%M")).strip(),
        "recovered": bool(recovered),
        "key": str(key or "").strip(),
    }



def _append_alert(alerts, severity, category, title, details="", source="", snapshot=None, recovered=False, key=""):
    alerts.append(_make_alert(
        severity=severity,
        category=category,
        title=title,
        details=details,
        source=source,
        time_text=_alert_time(snapshot),
        recovered=recovered,
        key=key,
    ))
