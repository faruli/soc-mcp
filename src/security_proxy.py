# src/security_proxy.py
"""
Security-Proxy & Mini-Dashboard
-------------------------------
- Liefert Health-/Audit-Infos und ein lokales Dashboard aus config.resources.dashboard
- Liest Pfade/Ports aus src/config.json
- Stellt JSON-Feeds für das Dashboard bereit:
    /_audit.json   -> Audit-Events (JSONL)
    /_alerts.json  -> Roh-Alerts    (JSONL)
    /_enrich.json  -> Enrichment    (JSONL)
- MCP-fähig (FastApiMCP), sodass z. B. Claude Desktop Tools sieht (health, get_audit)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional, List

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi_mcp import FastApiMCP
import time
from src.utils.audit import log_action


# ------------------------- Mini-Config-Loader ------------------------- #
def _resolve_paths(base: Path, node: Any) -> Any:
    if isinstance(node, dict):
        out: Dict[str, Any] = {}
        for k, v in node.items():
            if k in {"log_file", "dashboard"} and isinstance(v, str):
                p = Path(v)
                v = str((base / p).resolve()) if not p.is_absolute() else str(p)
            out[k] = _resolve_paths(base, v)
        return out
    if isinstance(node, list):
        return [_resolve_paths(base, x) for x in node]
    return node

def load_config(config_path: Optional[Path] = None) -> Dict[str, Any]:
    base = Path(__file__).parent
    cfg_path = config_path or (base / "config.json")
    if not cfg_path.exists():
        raise RuntimeError(f"Konfigurationsdatei fehlt: {cfg_path}")
    raw = json.loads(cfg_path.read_text(encoding="utf-8"))
    return _resolve_paths(base, raw)

CFG = load_config()
RES = CFG.get("resources", {}) or {}

# ------------------------- Pfade & Dateien ---------------------------- #
# Dashboard-Pfad kann Datei ODER Ordner sein:
_dashboard_cfg = RES.get("dashboard", "dashboard/index.html")
DASHBOARD_PATH = Path(_dashboard_cfg).resolve()
DASHBOARD_DIR = (DASHBOARD_PATH if DASHBOARD_PATH.is_dir() else DASHBOARD_PATH.parent).resolve()

# Logs-Verzeichnis (Standard: src/logs)
LOG_DIR = (Path(__file__).parent / "logs").resolve()

# Audit-Datei: tolerant gegenüber mehreren Namen
_AUDIT_CANDIDATES = [
    Path(RES.get("log_file", "")) if RES.get("log_file") else None,
    LOG_DIR / "_audit.json",
    LOG_DIR / "audit.jsonl",
    LOG_DIR / "_audit.jsonl",
    LOG_DIR / "audit.json",
]
AUDIT_FILE = next((p for p in _AUDIT_CANDIDATES if p and p.exists()), _AUDIT_CANDIDATES[1])

# Alerts & Enrich JSONL (werden vom soc_server geschrieben)
ALERTS_FILE = (LOG_DIR / "_alerts.json").resolve()
ENRICH_FILE = (LOG_DIR / "_enrich.json").resolve()

# ------------------------- App --------------------------------------- #
app = FastAPI(
    title="SOC Security Proxy",
    version="1.1.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# HTTP-Audit-Middleware ---

@app.middleware("http")
async def _http_audit(request, call_next):
    t0 = time.perf_counter()
    resp = None
    try:
        resp = await call_next(request)
        return resp
    finally:
        try:
            dt = (time.perf_counter() - t0) * 1000.0
            log_action("http", {
                "method": request.method,
                "path": request.url.path,
                "status": int(getattr(resp, "status_code", 500) if resp else 500),
                "duration_ms": round(dt, 2),
            })
        except Exception:
            pass

# Dashboard / Static
print(f"[dashboard] dir={DASHBOARD_DIR} index={DASHBOARD_DIR / 'index.html'} exists={(DASHBOARD_DIR / 'index.html').exists()}")

@app.get("/", include_in_schema=False)
def root_redirect():
    return RedirectResponse(url="/dashboard/")

@app.get("/dashboard", include_in_schema=False)
def dashboard_redirect():
    # /dashboard -> /dashboard/  (wichtig für StaticFiles & Trailing Slash)
    return RedirectResponse(url="/dashboard/")

# Verzeichnis mounten, liefert bei /dashboard/ automatisch die index.html
if DASHBOARD_DIR.exists() and DASHBOARD_DIR.is_dir():
    app.mount(
        "/dashboard",
        StaticFiles(directory=str(DASHBOARD_DIR), html=True),
        name="dashboard",
    )

# Fallback, falls kein Ordner gemountet werden konnte, wird die direkte Datei ausgeliefert
@app.get("/dashboard/", response_class=HTMLResponse, include_in_schema=False)
def dashboard_fallback():
    index_file = (DASHBOARD_DIR / "index.html")
    if index_file.exists():
        return HTMLResponse(index_file.read_text(encoding="utf-8"))
    if DASHBOARD_PATH.exists() and DASHBOARD_PATH.is_file():
        return HTMLResponse(DASHBOARD_PATH.read_text(encoding="utf-8"))
    raise HTTPException(status_code=404, detail="Dashboard nicht gefunden")


# ------------------------- JSONL Reader -------------------------------- #
def _read_jsonl_tail(path: Path, limit: int = 100) -> List[Dict[str, Any]]:
    """
    Liest die letzten N Objekte aus einer JSONL-Datei (ein JSON pro Zeile).
    Gibt jüngste Einträge zuerst zurück.
    """
    if not path.exists():
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return []
    rows: List[Dict[str, Any]] = []
    for ln in lines[-max(1, min(limit, 5000)):]:
        ln = ln.strip()
        if not ln:
            continue
        try:
            rows.append(json.loads(ln))
        except Exception:
            # Tolerant gegenüber Mischformaten
            try:
                obj = json.loads(ln.rstrip(","))
                if isinstance(obj, dict):
                    rows.append(obj)
            except Exception:
                continue
    # jüngste oben
    rows.reverse()
    return rows


# ------------------------- Health ------------------------------------- #
@app.get("/_health", summary="Health", operation_id="health")
def health():
    dash_ok = (DASHBOARD_DIR / "index.html").exists() or (DASHBOARD_PATH.exists() and DASHBOARD_PATH.is_file())
    return {
        "status": "ok" if dash_ok else "degraded",
        "dashboard_dir": str(DASHBOARD_DIR),
        "dashboard_path": str(DASHBOARD_PATH),
        "audit_file": str(AUDIT_FILE),
        "alerts_file": str(ALERTS_FILE),
        "enrich_file": str(ENRICH_FILE),
        "alerts_exists": ALERTS_FILE.exists(),
        "enrich_exists": ENRICH_FILE.exists(),
    }


# ------------------------- JSON Feeds fürs Dashboard ------------------ #
# Audit (JSONL -> JSON)
@app.get("/_audit.json", summary="Audit (JSON)", operation_id="get_audit")
def get_audit(limit: int = Query(100, ge=1, le=2000)):
    rows = _read_jsonl_tail(AUDIT_FILE, limit)
    # Backwards-compat: einige UIs erwarten "items", andere "rows"
    return {"items": rows, "rows": rows, "count": len(rows)}

# Roh-Alerts (vom SOC-Server geschrieben)
@app.get("/_alerts.json", summary="Alerts (JSON)", operation_id="get_alerts")
def get_alerts(limit: int = Query(100, ge=1, le=2000)):
    rows = _read_jsonl_tail(ALERTS_FILE, limit)
    return {"items": rows, "rows": rows, "count": len(rows)}

# Enrichment-Resultate (vom SOC-Server geschrieben)
@app.get("/_enrich.json", summary="Enrichment (JSON)", operation_id="get_enrich")
def get_enrich(limit: int = Query(100, ge=1, le=2000)):
    rows = _read_jsonl_tail(ENRICH_FILE, limit)
    return {"items": rows, "rows": rows, "count": len(rows)}


# ------------------------- MCP Mount ---------------------------------- #
mcp = FastApiMCP(app)
mcp.mount_http()    # stellt /mcp bereit
mcp.setup_server()  # registriert FastAPI-Routen als MCP-Tools (wichtig!)


# ------------------------- __main__ Start ------------------------------ #
if __name__ == "__main__":
    import uvicorn
    p_cfg = CFG.get("proxy", {}) or {}
    s_cfg = CFG.get("server", {}) or {}
    host   = p_cfg.get("host", s_cfg.get("host", "127.0.0.1"))
    port   = int(p_cfg.get("port", 8010))
    reload = bool(p_cfg.get("reload", s_cfg.get("reload", False)))
    uvicorn.run(app, host=host, port=port, reload=reload)
