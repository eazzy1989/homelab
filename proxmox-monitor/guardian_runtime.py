#!/usr/bin/env python3
"""Laufzeit-Hilfen für Proxmox Guardian.

Enthält bewusst nur kleine, abhängigkeitsfreie Bausteine:

* RedactingFilter  - entfernt Bot-Tokens / API-Token-Secrets aus Logzeilen
* JsonStore        - thread-sicherer, atomarer JSON-Speicher
* UiState          - Menü-Zustand getrennt pro Telegram-Chat
* Outbox           - Zwischenspeicher für nicht zustellbare Alarme
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable

_TOKEN_PATTERNS = [
    # Telegram-Bot-Token (auch innerhalb von URLs: /bot<TOKEN>/method)
    (re.compile(r"\d{6,12}:[A-Za-z0-9_-]{30,}"), "<BOT_TOKEN>"),
    # Proxmox-API-Token: PVEAPIToken=user@realm!name=<uuid>
    (re.compile(r"(PVEAPIToken=[^=\s]+=)[0-9a-fA-F-]{20,}"), r"\1<REDACTED>"),
]


def redact(text: Any) -> str:
    s = str(text)
    for pattern, repl in _TOKEN_PATTERNS:
        s = pattern.sub(repl, s)
    return s


class RedactingFilter(logging.Filter):
    """Schwärzt Secrets in jeder Logzeile, bevor sie geschrieben wird."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:
            return True
        clean = redact(msg)
        if record.exc_info and not record.exc_text:
            record.exc_text = logging.Formatter().formatException(record.exc_info)
        if record.exc_text:
            record.exc_text = redact(record.exc_text)
        record.msg = clean
        record.args = ()
        return True


class JsonStore:
    """Thread-sicherer JSON-Speicher mit atomarem Schreiben (tmp + fsync + rename)."""

    def __init__(self, path: str | Path, default: Any):
        self.path = Path(path)
        self._default = default
        self._lock = threading.RLock()

    def _read(self) -> Any:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            return json.loads(json.dumps(self._default))

    def _write(self, data: Any) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(self.path.parent), prefix=f".{self.path.name}.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False, indent=2)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                try:
                    os.unlink(tmp)
                except OSError:
                    pass

    def load(self) -> Any:
        with self._lock:
            return self._read()

    def update(self, mutator: Callable[[Any], Any]) -> Any:
        with self._lock:
            data = self._read()
            result = mutator(data)
            self._write(data)
            return result


class UiState:
    """Menü-Zustand je Chat.

    Vorher lag der Zustand global in state.json und wurde
    (a) vom Monitor-Zyklus alle 2 Minuten überschrieben und
    (b) zwischen beiden Accounts geteilt.
    """

    def __init__(self, path: str | Path):
        self.store = JsonStore(path, {"menus": {}, "rendered": {}})

    def get_menu(self, chat_id: Any) -> int | None:
        data = self.store.load()
        entry = (data.get("menus") or {}).get(str(chat_id)) or {}
        mid = entry.get("message_id")
        return int(mid) if mid else None

    def set_menu(self, chat_id: Any, message_id: Any, view: str = "home") -> None:
        def mut(d):
            d.setdefault("menus", {})[str(chat_id)] = {
                "message_id": message_id,
                "view": view,
                "ts": int(time.time()),
            }
        self.store.update(mut)

    def is_unchanged(self, chat_id: Any, message_id: Any, body: str, view: str) -> bool:
        key = f"{chat_id}:{message_id}"
        digest = f"{view}|{hashlib.sha1(str(body).encode('utf-8', 'ignore')).hexdigest()}"
        data = self.store.load()
        return (data.get("rendered") or {}).get(key) == digest

    def remember_render(self, chat_id: Any, message_id: Any, body: str, view: str) -> None:
        key = f"{chat_id}:{message_id}"
        digest = f"{view}|{hashlib.sha1(str(body).encode('utf-8', 'ignore')).hexdigest()}"

        def mut(d):
            rendered = d.setdefault("rendered", {})
            rendered[key] = digest
            # begrenzen: nur die letzten 50 Nachrichten merken
            if len(rendered) > 50:
                for k in list(rendered.keys())[:-50]:
                    rendered.pop(k, None)
        self.store.update(mut)


class Outbox:
    """Alarme, die nicht zugestellt werden konnten (z. B. Internet-Ausfall).

    Werden bei jedem Zyklus erneut versucht und mit Hinweis auf den
    ursprünglichen Zeitpunkt zugestellt. Einträge älter als max_age
    werden verworfen (und geloggt), damit sich nichts unbegrenzt staut.
    """

    def __init__(self, path: str | Path, max_entries: int = 100, max_age: int = 24 * 3600):
        self.store = JsonStore(path, [])
        self.max_entries = max_entries
        self.max_age = max_age

    def add(self, chat_id: Any, text: str, reply_markup: dict | None = None) -> None:
        def mut(items):
            items.append({
                "chat_id": str(chat_id),
                "text": text,
                "reply_markup": reply_markup,
                "created_ts": int(time.time()),
                "attempts": 0,
            })
            del items[:-self.max_entries]
        self.store.update(mut)

    def pending(self) -> int:
        return len(self.store.load() or [])

    def flush(self, sender: Callable[[str, str, dict | None], bool], log: Callable[[str], None] | None = None) -> int:
        """sender(chat_id, text, reply_markup) -> True bei Erfolg. Liefert Anzahl zugestellter."""
        items = self.store.load() or []
        if not items:
            return 0
        now = int(time.time())
        delivered = 0
        remaining = []
        for item in items:
            age = now - int(item.get("created_ts", now))
            if age > self.max_age:
                if log:
                    log(f"Outbox: Alarm verworfen (älter als {self.max_age // 3600} h) chat={item.get('chat_id')}")
                continue
            stamp = time.strftime("%d.%m. %H:%M", time.localtime(item.get("created_ts", now)))
            text = f"⏱ Verspätet zugestellt (Ereignis {stamp})\n\n{item.get('text', '')}"
            ok = False
            try:
                ok = bool(sender(item["chat_id"], text, item.get("reply_markup")))
            except Exception:
                ok = False
            if ok:
                delivered += 1
            else:
                item["attempts"] = int(item.get("attempts", 0)) + 1
                remaining.append(item)
                # Wenn der erste Versand scheitert, ist die Verbindung
                # vermutlich noch weg -> Rest beim nächsten Zyklus.
                remaining.extend(i for i in items[items.index(item) + 1:]
                                 if now - int(i.get("created_ts", now)) <= self.max_age)
                break

        def mut(current):
            # Einträge, die während des Flush hinzukamen, erhalten
            known = {(i.get("chat_id"), i.get("created_ts"), i.get("text")) for i in items}
            added = [i for i in current if (i.get("chat_id"), i.get("created_ts"), i.get("text")) not in known]
            current[:] = remaining + added
        self.store.update(mut)
        return delivered
