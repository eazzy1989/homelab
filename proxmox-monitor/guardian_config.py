from __future__ import annotations

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
STATE_FILE = BASE_DIR / "guardian_state.json"
SNAPSHOT_FILE = BASE_DIR / "guardian_snapshot.json"
LOG_FILE = BASE_DIR / "guardian.log"

CHECK_INTERVAL = 15
POLL_INTERVAL = 5

CPU_WARN = 85.0
CPU_CRIT = 95.0
RAM_WARN = 85.0
RAM_CRIT = 95.0
ROOTFS_WARN = 85.0
ROOTFS_CRIT = 95.0
TEMP_WARN = 75.0
TEMP_CRIT = 85.0
STORAGE_WARN = 85.0
STORAGE_CRIT = 95.0
BACKUP_AGE_WARN_DAYS = 7

CPU_SUSTAIN_SECONDS = 300
RAM_SUSTAIN_SECONDS = 300
STORAGE_SUSTAIN_SECONDS = 300
TEMP_SUSTAIN_SECONDS = 180

LEGACY_ALERT_SENDING_ENABLED = False

# Warnungen dieser Kategorien werden per Telegram gemeldet und zählen in den
# Health Score. Kritische Alarme werden immer gemeldet.
NOTIFY_WARNING_CATEGORIES = {
    "backup", "storage", "smart", "qemu", "lxc", "network", "zfs", "raid",
    "vm_resource", "vm", "lxc_resource", "system",
}

CATEGORY_LABELS = {
    "hardware": "Hardware",
    "storage": "Storage",
    "network": "Netzwerk",
    "backup": "Backup",
    "qemu": "QEMU",
    "lxc": "LXC",
    "system": "System",
    "security": "Security",
    "updates": "Updates",
    "telegram": "Telegram",
}

SEVERITY_ORDER = {
    "info": 0,
    "warning": 1,
    "critical": 2,
}

ALERT_ICONS = {
    "info": "✅",
    "warning": "⚠️",
    "critical": "🚨",
}
