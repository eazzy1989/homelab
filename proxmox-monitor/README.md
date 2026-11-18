# Proxmox Monitor

Überwachung des **Proxmox-VE-Hosts** per Telegram – das Gegenstück zu [Ubuntu Guardian](https://github.com/eazzy1989/ubuntu-guardian), das die VMs von innen überwacht. Rund 8.000 Zeilen Python, aufgeteilt in fachliche Module.

## Was überwacht wird

| Bereich | Module |
|---|---|
| Host | CPU, RAM, Load, Temperaturen, Kernel, ausstehende Updates, Neustart nötig |
| VMs & Container | Status, Ressourcenverbrauch, unerwartete Stopps (`guardian_vms`, `guardian_lxc`, `guardian_guest_stop`) |
| Speicher | Belegung, LVM/ZFS-Zustand, RAID, SMART-Werte (`guardian_storage*`, `guardian_zfs`, `guardian_raid`, `guardian_smart`) |
| Backups | letzte vzdump-Sicherungen je Gast, fehlgeschlagene Jobs, Proxmox Backup Server (`guardian_backup`, `guardian_pbs`) |
| Cluster (optional) | Corosync, HA, Replikation, Ceph – werden automatisch übersprungen, wenn nicht vorhanden |
| Netzwerk | Ping- und Port-Checks, DNS, Internet, Wechsel der öffentlichen IP, Auswertung von WAN-Ausfällen |
| Sicherheit | SSH-Konfiguration, offene Updates (`guardian_security*`) |

## Bedienung über Telegram

Menü mit Buttons für Host, Status, Speicher, VMs (`/qemu`), Container (`/lxc`), Netzwerk, Temperaturen, SMART, Backups, Alarme und Logs – plus kontrollierter Neustart und Update-Installation direkt aus dem Chat.

Alarme werden dedupliziert, mit Ursache, Schwelle und aktuellem Wert formatiert und bei Telegram-Störungen in einer Warteschlange zwischengespeichert. Tokens werden in Logs automatisch geschwärzt.

## Installation

```bash
sudo mkdir -p /opt/proxmox-monitor && sudo cp *.py requirements.txt /opt/proxmox-monitor/
cd /opt/proxmox-monitor
python3 -m venv venv && venv/bin/pip install -r requirements.txt
cp .env.example .env && nano .env && chmod 600 .env
sudo cp proxmox-monitor.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now proxmox-monitor
```

Für die Proxmox-API einen eigenen Benutzer mit **API-Token** und nur lesenden Rechten (Rolle `PVEAuditor`) anlegen – nicht das root-Passwort verwenden.

## Hinweis

Die WAN-, Geräte- und Provider-Ansichten (`guardian_wan.py`) werten CSV-Dateien aus, die separate Mess-Skripte auf meinem Host schreiben. Diese Skripte sind nicht Teil des Repos; ohne sie zeigen die Ansichten einfach „keine Daten“.
