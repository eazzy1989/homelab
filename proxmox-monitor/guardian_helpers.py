#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import tempfile
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any


def now_ts() -> int:
    return int(time.time())


def iso_ts(ts: int | float | None = None) -> str:
    value = int(ts or now_ts())
    return datetime.fromtimestamp(value).strftime("%Y-%m-%d %H:%M:%S")


def safe_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value).strip()


def stable_hash(*parts: Any) -> str:
    raw = "||".join(safe_str(p) for p in parts)
    return hashlib.sha1(raw.encode("utf-8", errors="ignore")).hexdigest()[:16]


def load_json(path: str | Path, default: Any = None) -> Any:
    try:
        p = Path(path)
        if p.exists():
            return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {} if default is None else default


def save_json(path: str | Path, data: Any) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", delete=False, dir=str(p.parent), encoding="utf-8") as tmp:
        json.dump(data, tmp, ensure_ascii=False, indent=2)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_name = tmp.name
    os.replace(tmp_name, p)


def fmt_pct(value: Any) -> str:
    try:
        return f"{float(value):.1f}%"
    except Exception:
        return "n/a"


def fmt_bytes(num: Any) -> str:
    try:
        value = float(num)
    except Exception:
        return "n/a"
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    for unit in units:
        if abs(value) < 1024.0 or unit == units[-1]:
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024.0
    return "n/a"


def ensure_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]

def clamp_float(value, minimum=0.0, maximum=100.0, default=0.0) -> float:
    try:
        x = float(value)
    except Exception:
        x = float(default)
    if x < minimum:
        return float(minimum)
    if x > maximum:
        return float(maximum)
    return float(x)
