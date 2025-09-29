# src/utils/audit.py
"""
Einfaches Audit-Logging (JSON Lines / JSONL).

- Liest Zielpfad aus CONFIG_PATH (Umgebungsvariable) oder src/config.json -> resources.log_file.
- Fallback: src/logs/audit.jsonl
- Schreibt pro Ereignis genau eine JSON-Zeile (append).
- Zeitstempel sind timezone-aware (UTC) im ISO8601-Format, normalisiert auf 'Z'.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

# --- Zeitstempel: UTC (ohne Deprecation-Warnung, kompatibel) ---
from datetime import datetime
try:
    # Python 3.11+
    from datetime import UTC  # type: ignore[attr-defined]
except ImportError:  # Python < 3.11
    from datetime import timezone as _tz  # type: ignore
    UTC = _tz.utc  # type: ignore


# ----------------------------- Konfig-Helper -----------------------------
BASE = Path(__file__).resolve().parent.parent  # .../src

def _resolve_paths(base: Path, node: Any) -> Any:
    """Ersetzt relative Pfade in config.json durch absolute Pfade (z. B. resources.log_file)."""
    if isinstance(node, dict):
        out: Dict[str, Any] = {}
        for k, v in node.items():
            if k in {"log_file", "dashboard"} and isinstance(v, str):
                p = Path(v)
                v = str(p if p.is_absolute() else (base / p).resolve())
            out[k] = _resolve_paths(base, v)
        return out
    if isinstance(node, list):
        return [_resolve_paths(base, x) for x in node]
    return node

def _load_cfg(config_path: Optional[Path] = None) -> Dict[str, Any]:
    """
    Lädt CONFIG_PATH (wenn gesetzt) oder src/config.json.
    Gibt {} zurück, falls nicht vorhanden oder ungültig.
    """
    cfg_path = config_path
    if cfg_path is None:
        env_cfg = os.getenv("CONFIG_PATH")
        cfg_path = Path(env_cfg) if env_cfg else (BASE / "config.json")

    try:
        if cfg_path.exists():
            raw = json.loads(cfg_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                return _resolve_paths(BASE, raw)  # type: ignore[return-value]
    except Exception:
        pass
    return {}

def _log_file_path(override: Optional[Path] = None) -> Path:
    """
    Ermittelt den Log-Pfad:
      1) expliziter Parameter (override), sonst
      2) resources.log_file aus config.json (mit CONFIG_PATH-Support), sonst
      3) Fallback: src/logs/audit.jsonl
    """
    if override:
        return Path(override).resolve()

    cfg = _load_cfg()
    res = cfg.get("resources", {}) if isinstance(cfg, dict) else {}
    path_str = res.get("log_file") if isinstance(res, dict) else None
    if isinstance(path_str, str) and path_str.strip():
        p = Path(path_str)
        return p if p.is_absolute() else (BASE / p).resolve()

    return (BASE / "logs" / "audit.jsonl").resolve()


# ----------------------------- Öffentliches API -----------------------------
def log_action(action: str, details: Dict[str, Any], *, log_file: Optional[Path] = None) -> None:
    """
    Schreibt einen Audit-Eintrag als JSON-Linie in die Logdatei.

    Beispiel:
        log_action("test", {"method":"GET","path":"/attack/T1059","status":200,"duration_ms":12.3})
    """
    target = _log_file_path(log_file)
    target.parent.mkdir(parents=True, exist_ok=True)

    # timezone-aware UTC; Offset +00:00 -> 'Z' normalisieren
    ts = datetime.now(UTC).isoformat().replace("+00:00", "Z")

    entry = {
        "timestamp": ts,
        "action": action,
        "details": details,
    }

    with open(target, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False))
        f.write("\n")
