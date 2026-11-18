"""Telegram-Anbindung für Proxmox Guardian.

Öffentliche Schnittstelle unverändert (configure, escape_tg, safe_telegram_text,
telegram_api, send_telegram, edit_telegram, answer_callback), ergänzt um:

* Fehler werden geloggt (Token wird durch den RedactingFilter geschwärzt)
* HTTP 429 (Flood-Limit): einmaliger Retry nach retry_after (max. 30 s)
* HTML-Parse-Fehler: automatischer Retry als Klartext statt stillem Verlust
* Nachrichten werden auf das Telegram-Limit gekürzt
* Thread-lokale HTTP-Sessions (Monitor-Thread, Poll-Loop, Worker)
"""
import html
import logging
import re
import threading
import time
from typing import Any

import requests

BOT_TOKEN = ""
CHAT_ID = ""
CHAT_IDS: list[str] = []
TELEGRAM_MSG_LIMIT = 4096

logger = logging.getLogger("proxmox_guardian.telegram")
_local = threading.local()


def configure(bot_token: str, chat_id: str, msg_limit: int = 4096, chat_ids: list[str] | None = None):
    global BOT_TOKEN, CHAT_ID, TELEGRAM_MSG_LIMIT, CHAT_IDS
    BOT_TOKEN = bot_token
    CHAT_ID = chat_id
    TELEGRAM_MSG_LIMIT = msg_limit
    CHAT_IDS = [str(x).strip() for x in (chat_ids or ([chat_id] if chat_id else [])) if str(x).strip()]


def _session() -> requests.Session:
    s = getattr(_local, "session", None)
    if s is None:
        s = requests.Session()
        _local.session = s
    return s


def escape_tg(text: Any) -> str:
    return html.escape(str(text), quote=False)


def safe_telegram_text(text: Any, hard_limit: int | None = None) -> str:
    limit = hard_limit or TELEGRAM_MSG_LIMIT
    s = str(text or "")
    if len(s) <= limit:
        return s
    cut = s.rfind("\n", 0, limit - 2)
    if cut <= 0:
        return s[: limit - 1] + "…"
    return s[:cut].rstrip() + "\n…"


_TAG_RE = re.compile(r"</?(b|i|u|s|code|pre|a)(\s[^>]*)?>", re.IGNORECASE)


def _to_plain(text: str) -> str:
    """HTML-Text in lesbaren Klartext wandeln (für den Parse-Fehler-Fallback)."""
    return html.unescape(_TAG_RE.sub("", str(text or "")))


def _post(method: str, payload: dict, timeout: int) -> dict | None:
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/{method}"
    r = _session().post(url, json=payload, timeout=timeout)
    try:
        return r.json()
    except ValueError:
        return {"ok": False, "error_code": r.status_code, "description": f"HTTP {r.status_code} ohne JSON"}


def telegram_api(method, payload=None):
    if not BOT_TOKEN:
        return None

    payload = dict(payload or {})
    try:
        if method == "getUpdates":
            poll_timeout = int(payload.get("timeout", 0) or 0)
            url = f"https://api.telegram.org/bot{BOT_TOKEN}/getUpdates"
            params = dict(payload)
            if isinstance(params.get("allowed_updates"), list):
                import json as _json
                params["allowed_updates"] = _json.dumps(params["allowed_updates"])
            try:
                r = _session().get(url, params=params, timeout=poll_timeout + 15)
            except requests.exceptions.ReadTimeout:
                return {"ok": True, "result": []}
            data = r.json()
            if not data.get("ok"):
                logger.warning("Telegram getUpdates Fehler: %s", data.get("description"))
            return data

        data = _post(method, payload, timeout=20)

        # Flood-Limit: einmal warten und erneut versuchen
        if data and data.get("error_code") == 429:
            retry_after = int(((data.get("parameters") or {}).get("retry_after")) or 1)
            if retry_after <= 30:
                logger.warning("Telegram %s: Flood-Limit, warte %s s", method, retry_after)
                time.sleep(retry_after)
                data = _post(method, payload, timeout=20)

        # HTML-Parse-Fehler: als Klartext erneut senden, statt die Nachricht zu verlieren
        if (
            data
            and not data.get("ok")
            and method in ("sendMessage", "editMessageText")
            and "parse entities" in str(data.get("description", "")).lower()
        ):
            logger.warning("Telegram %s: HTML ungültig (%s) – sende als Klartext", method, data.get("description"))
            plain = dict(payload)
            plain.pop("parse_mode", None)
            plain["text"] = safe_telegram_text(_to_plain(payload.get("text", "")))
            data = _post(method, plain, timeout=20)

        if data and not data.get("ok"):
            desc = str(data.get("description", ""))
            # Erwartete, harmlose Antworten nicht als Fehler loggen
            harmless = ("message is not modified", "query is too old", "message to delete not found",
                        "message can't be deleted")
            if not any(h in desc.lower() for h in harmless):
                logger.warning("Telegram %s fehlgeschlagen: %s", method, desc)
        return data

    except Exception as exc:  # Netzwerkfehler etc.
        logger.warning("Telegram %s nicht erreichbar: %s", method, exc)
        return None


def send_telegram(text, chat_id=None, reply_markup=None):
    target_chat = str(chat_id or CHAT_ID).strip()
    if not BOT_TOKEN or not target_chat:
        return None

    payload = {
        "chat_id": target_chat,
        "text": safe_telegram_text(text),
        "parse_mode": "HTML",
    }

    if reply_markup:
        payload["reply_markup"] = reply_markup

    return telegram_api("sendMessage", payload)


def edit_telegram(chat_id, message_id, text, reply_markup=None):
    payload = {
        "chat_id": chat_id,
        "message_id": message_id,
        "text": safe_telegram_text(text),
        "parse_mode": "HTML",
    }

    if reply_markup:
        payload["reply_markup"] = reply_markup

    return telegram_api("editMessageText", payload)


def answer_callback(callback_query_id, text="OK"):
    return telegram_api(
        "answerCallbackQuery",
        {
            "callback_query_id": callback_query_id,
            "text": text,
        },
    )
