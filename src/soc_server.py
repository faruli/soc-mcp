"""
SOC-Server (FastAPI + MCP)
--------------------------
Endpunkte (Auszug):
- POST /alerts/ingest             -> nimmt Alerts an, triggert Auto-Enrichment (BackgroundTasks)
- GET  /attack/{tech_id}          -> lokale Daten (JSON/py), 404 wenn nicht gefunden
- GET  /attack/live/{tech_id}     -> MITRE ATT&CK live via TAXII 2.1 (STIX)
- POST /splunk/search             -> Mock-Ergebnis
- POST /cases/                    -> einfaches "Case" anlegen
- GET  /cve/{cve_id}              -> Dummy (wird in Unit-Tests gemockt)
- GET  /cve/live/{cve_id}         -> CVE live via NVD API v2 (Flag noRejected, User-Agent, apiKey)
- GET  /malware/{hash}            -> VirusTotal v3, ENV: VIRUSTOTAL_API_KEY
- POST /splunk/export             -> Splunk Export (REST v2) + CSV-Mock (config.json)
- POST /sentinel/query            -> Azure Monitor Logs (Sentinel) Workspace Query + CSV-Mock (config.json)
- GET  /_health/nvd               -> Health-Check für NVD-API/Key
- GET  /_health/taxii             -> Health-Check für MITRE TAXII (Enterprise-Collection)
- MCP  /mcp                       -> HTTP (SSE/HTTP) via FastApiMCP
"""

from __future__ import annotations

import os
import time
import json
import ast
import re
import csv
import importlib.util
from functools import lru_cache
from pathlib import Path
from dotenv import load_dotenv
from typing import Any, Dict, List, Optional, TYPE_CHECKING, Set, Tuple
from time import perf_counter

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from fastapi import FastAPI, HTTPException, BackgroundTasks, status
from pydantic import BaseModel
from fastapi_mcp import FastApiMCP
from src.utils.audit import log_action  # Audit-Log

LOG_DIR = Path(__file__).parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

# .env neben dieser Datei laden (src/.env)
load_dotenv(dotenv_path=Path(__file__).parent / ".env")

# Optionale TAXII/STIX-Imports sind zur Laufzeit evtl. nicht vorhanden
try:
    from taxii2client.v21 import Server, Collection  # type: ignore
except Exception:
    Server = Collection = None  # type: ignore

# Nur zur Typprüfung – wird nicht zur Laufzeit importiert
if TYPE_CHECKING:
    from stix2 import TAXIICollectionSource as TaxiiSourceType
else:
    TaxiiSourceType = Any  # Fallback zur Laufzeit


def _append_jsonl(path: Path, obj: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


# --- Config -------------------------------------------------
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
        return {}
    raw = json.loads(cfg_path.read_text(encoding="utf-8"))
    return _resolve_paths(base, raw)

CFG = load_config()

# CSV-Mock-Quellen aus config.json
DATASETS_CFG_SPLUNK  = (CFG.get("datasets", {}) or {}).get("splunk", {}) or {}
DATASETS_CFG_SENTINEL = (CFG.get("datasets", {}) or {}).get("sentinel", {}) or {}


# --- App & MCP ---------------------------------------------------------------
app = FastAPI(
    title="SOC Server",
    version="1.1.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# HTTP-Audit-Middleware direkt NACH app = FastAPI(...)
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

mcp = FastApiMCP(app)
mcp.mount_http()  # /mcp


# --- Modelle (Pydantic) ------------------------------------------------------
class SplunkQuery(BaseModel):
    query: str

class CaseCreate(BaseModel):
    title: str
    severity: str
    context: Dict[str, Any] = {}

class SplunkExportBody(BaseModel):
    query: str
    base: Optional[str] = "https://splunk.local:8089"
    token: Optional[str] = None

class SentinelQueryBody(BaseModel):
    workspace_id: str
    kql: str
    token: Optional[str] = None
    timespan: Optional[str] = "PT1H"


# --- ATT&CK: lokale Daten ----------------------------------------------------
DATA_DIR = Path(__file__).parent / "data"
DATA_JSON = DATA_DIR / "attack_techniques.json"
DATA_PY = Path(__file__).parent / "attack_techniques.py"

def load_attack_data() -> List[Dict[str, Any]]:
    """Liest Attack-Techniken: 1) aus JSON (bevorzugt), 2) optional aus .py (Fallback)."""
    if DATA_JSON.exists():
        text = DATA_JSON.read_text(encoding="utf-8")
        data = json.loads(text)
        if isinstance(data, list):
            return data
        raise RuntimeError("attack_techniques.json must contain a top-level list")
    if DATA_PY.exists():
        try:
            spec = importlib.util.spec_from_file_location("attack_techniques", DATA_PY)
            mod = importlib.util.module_from_spec(spec)  # type: ignore
            assert spec.loader is not None
            spec.loader.exec_module(mod)  # type: ignore
            data = getattr(mod, "ATTACK_TECHNIQUES", None)
            if isinstance(data, list):
                return data
        except Exception:
            pass
        try:
            text_py = DATA_PY.read_text(encoding="utf-8")
            data = ast.literal_eval(text_py)
            if isinstance(data, list):
                return data
        except Exception:
            pass
    return []


# --- ENRICH: Einstellungen, Regex & HTTP-Session mit Retry -------------------
SOC_ENRICH = os.getenv("SOC_ENRICH", "1") == "1"
SOC_ENRICH_OFFLINE = os.getenv("SOC_ENRICH_OFFLINE", "0") == "1"
SOC_ENRICH_MAX_CVES = int(os.getenv("SOC_ENRICH_MAX_CVES", "3"))
NVD_API_KEY = os.getenv("NVD_API_KEY")

# ------------- Regex (CVE & MITRE-Techniken) ------------------------
CVE_RX = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
TECH_RX = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)

def _session_with_retry() -> requests.Session:
    """requests.Session mit Retries & Exponential Backoff (429/5xx)."""
    s = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET", "POST"),
    )
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.mount("http://", HTTPAdapter(max_retries=retry))
    return s

S = _session_with_retry()

def _extract_ids(alert: Dict[str, Any]) -> Tuple[Set[str], Set[str]]:
    """Extrahiert CVEs & Techniken aus Description/Evidence/Entities."""
    text = " ".join(filter(None, [
        alert.get("Description"),
        (alert.get("Evidence") or {}).get("Message"),
        json.dumps(alert.get("Entities", {}), ensure_ascii=False)
    ]))
    cves = {m.upper() for m in CVE_RX.findall(text)}
    techs = {m.upper() for m in TECH_RX.findall(text)}
    if SOC_ENRICH_MAX_CVES and len(cves) > SOC_ENRICH_MAX_CVES:
        cves = set(list(cves)[:SOC_ENRICH_MAX_CVES])
    return cves, techs

def _nvd_lookup(cve: str) -> Dict[str, Any]:
    """NVD v2: CVE-Details via cveId-Parameter abrufen."""
    base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"User-Agent": "soc-mcp/1.1"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    r = S.get(base, params={"cveId": cve, "noRejected": None}, headers=headers, timeout=20)
    r.raise_for_status()
    return r.json()

def _attack_lookup_offline(tech: str) -> Dict[str, Any]:
    """Lokaler ATT&CK-Lookup aus JSON-Cache; für Live gibt es /attack/live/{tech}."""
    if DATA_JSON.exists():
        cache = json.loads(DATA_JSON.read_text(encoding="utf-8"))
        if isinstance(cache, list):
            for it in cache:
                if isinstance(it, dict) and it.get("technique_id") == tech:
                    return it
        elif isinstance(cache, dict):
            return cache.get(tech, {})
    return {}

def _cvss_base_from_nvd_v2(js: Dict[str, Any]) -> float:
    vulns = js.get("vulnerabilities") or []
    if not vulns:
        return 0.0
    metrics = (vulns[0].get("cve", {}).get("metrics") or {})
    v31 = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or []
    if v31 and isinstance(v31, list):
        return float(v31[0].get("cvssData", {}).get("baseScore", 0) or 0)
    return 0.0

def enrich_in_background(alert: Dict[str, Any]) -> None:
    """Auto-Enrichment: CVE + MITRE (offline Cache), Score/Severity ableiten, JSONL + Audit-Eintrag schreiben."""
    if not SOC_ENRICH:
        return
    findings: List[Dict[str, Any]] = []
    score = 50

    try:
        cves, techs = _extract_ids(alert)

        # CVEs → NVD v2
        for cve in cves:
            try:
                nvd = _nvd_lookup(cve)
                base = _cvss_base_from_nvd_v2(nvd)
                if base:
                    score = max(score, int(base) * 10)
                findings.append({"type": "CVE", "id": cve, "cvss": base})
            except Exception as e:
                findings.append({"type": "CVE", "id": cve, "error": str(e)})

        # ----------------- Techniken → ATT&CK (offline Cache; live wahlweise via /attack/live/{id}) --------
        for t in techs:
            try:
                ap = _attack_lookup_offline(t) or {}
                kc = " ".join(ap.get("kill_chain_phases") or [])
                if any(x in kc.lower() for x in ("execution", "defense evasion", "defense-evasion")):
                    score = max(score, 70)
                findings.append({"type": "MITRE", "id": t, "name": ap.get("name"), "kill_chain_phases": ap.get("kill_chain_phases")})
            except Exception as e:
                findings.append({"type": "MITRE", "id": t, "error": str(e)})

        severity = "high" if score >= 80 else "medium" if score >= 60 else "low"

        # JSONL für Dashboard (_enrich.json)
        _append_jsonl(LOG_DIR / "_enrich.json", {
            "ts": int(time.time()),
            "alert": alert,
            "summary": {"cves": sorted(cves), "techniques": sorted(techs), "score": score, "severity": severity}
        })

        # Audit-Event
        log_action("enrich", {
            "severity": severity,
            "score": score,
            "findings": findings,
            "alert": {"name": alert.get("AlertName"), "host": (alert.get("Entities") or {}).get("Host")},
        })

    except Exception as e:
        log_action("enrich_error", {"error": str(e)})


# --- Endpunkte ---------------------------------------------------------------
@app.post("/alerts/ingest", status_code=status.HTTP_202_ACCEPTED, operation_id="alerts_ingest")
def alerts_ingest(alert: Dict[str, Any], background_tasks: BackgroundTasks):
    """
    Nimmt einen Alert entgegen, schreibt JSONL (_alerts.json) und startet die Anreicherung im Hintergrund.
    Antwortet sofort (202), damit die UX/Demo flüssig bleibt.
    """
    # Roh-Alert für Dashboard (_alerts.json)
    try:
        _append_jsonl(LOG_DIR / "_alerts.json", {"ts": int(time.time()), "alert": alert})
    except Exception:
        pass

    # Audit
    try:
        log_action("ingest", {
            "alert_name": alert.get("AlertName"),
            "severity": alert.get("Severity"),
            "techniques": alert.get("Techniques"),
        })
    except Exception:
        pass

    # Enrichment asynchron
    background_tasks.add_task(enrich_in_background, alert)
    return {"status": "accepted", "enrich": bool(SOC_ENRICH)}


@app.get("/attack/{tech_id}", operation_id="attack_lookup")
def attack_lookup(tech_id: str):
    data = load_attack_data()
    for item in data:
        if isinstance(item, dict) and item.get("technique_id") == tech_id:
            return item
    raise HTTPException(status_code=404, detail="Technique not found")


# -------------- ROBUSTE TAXII-Helfer (MITRE ATT&CK live) ------------
ATTACK_TAXII_ROOT = "https://attack-taxii.mitre.org/api/v21/"
ENTERPRISE_COLLECTION_ID = "x-mitre-collection--1f5f1533-f617-4ca8-9ab4-6a02367fa019"

def _require_taxii():
    if Server is None or Collection is None:
        raise HTTPException(status_code=500, detail="taxii2-client/stix2 nicht installiert")

@lru_cache(maxsize=1)
def _enterprise_collection_url() -> str:
    _require_taxii()
    try:
        server = Server(ATTACK_TAXII_ROOT)  # type: ignore
        api_roots = list(server.api_roots or [])
        if api_roots:
            root = api_roots[0]
            cols = list(root.collections or [])
            for c in cols:
                if getattr(c, "id", "") == ENTERPRISE_COLLECTION_ID:
                    return c.url
            for c in cols:
                if "enterprise" in (getattr(c, "title", "") or "").lower():
                    return c.url
            if cols:
                return cols[0].url
    except Exception:
        pass

    try:
        coll_url = ATTACK_TAXII_ROOT.rstrip("/") + "/collections/"
        resp = requests.get(
            coll_url,
            headers={"Accept": "application/taxii+json; version=2.1"},
            timeout=20,
        )
        resp.raise_for_status()
        js = resp.json()
        cols = js.get("collections", []) or []
        for c in cols:
            if c.get("id") == ENTERPRISE_COLLECTION_ID:
                return ATTACK_TAXII_ROOT.rstrip("/") + "/collections/" + ENTERPRISE_COLLECTION_ID + "/"
        for c in cols:
            if "enterprise" in (c.get("title", "") or "").lower():
                return ATTACK_TAXII_ROOT.rstrip("/") + "/collections/" + c["id"] + "/"
        if cols:
            return ATTACK_TAXII_ROOT.rstrip("/") + "/collections/" + cols[0]["id"] + "/"
        raise HTTPException(status_code=502, detail="Keine TAXII-Collections gefunden (leer).")
    except requests.HTTPError as e:
        raise HTTPException(status_code=e.response.status_code, detail=f"TAXII collections fetch error: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"TAXII collections fetch failed: {e}")

@lru_cache(maxsize=1)
def _enterprise_source() -> "TaxiiSourceType":
    _require_taxii()
    from stix2 import TAXIICollectionSource  # type: ignore
    col_url = _enterprise_collection_url()
    collection = Collection(col_url)  # type: ignore
    return TAXIICollectionSource(collection)

def _find_attack_pattern(tech_id: str) -> Optional[Dict[str, Any]]:
    src = _enterprise_source()
    try:
        from stix2 import Filter  # type: ignore
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"stix2 Filter import failed: {e}")
    try:
        objects = src.query([Filter('type', '=', 'attack-pattern')])
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"TAXII query failed: {e}")
    for obj in objects:
        refs = obj.get("external_references") or []
        for ref in refs:
            src_name = (ref.get("source_name") or "").lower()
            if src_name in ("mitre-attack", "mitre-attack-mobile", "mitre-attack-ics"):
                if ref.get("external_id") == tech_id:
                    return dict(obj)
    return None

@app.get("/attack/live/{tech_id}", operation_id="attack_live")
def attack_live(tech_id: str):
    status_code: int = 500
    t0 = perf_counter()
    try:
        obj = _find_attack_pattern(tech_id)
        if not obj:
            status_code = 404
            raise HTTPException(status_code=404, detail="Technique not found")
        name = obj.get("name")
        desc = obj.get("description")
        kill_chain = [ph.get("phase_name") for ph in (obj.get("kill_chain_phases") or [])]
        status_code = 200
        return {
            "technique_id": tech_id,
            "name": name,
            "description": desc,
            "kill_chain_phases": kill_chain,
            "stix_id": obj.get("id"),
            "created": obj.get("created"),
            "modified": obj.get("modified"),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"ATT&CK lookup failed: {e}")
    finally:
        try:
            dt = (perf_counter() - t0) * 1000.0
            log_action("http", {
                "method": "GET",
                "path": f"/attack/live/{tech_id}",
                "status": int(status_code),
                "duration_ms": round(dt, 2),
            })
        except Exception:
            pass


# --- Splunk Mock & Cases -----------------------------------------------------
@app.post("/splunk/search", operation_id="splunk_search")
def splunk_search(body: SplunkQuery):
    return {
        "query": body.query,
        "results": [
            {"_time": "2025-09-14T10:00:00Z", "host": "srv01", "event": "failed login"},
            {"_time": "2025-09-14T10:05:00Z", "host": "srv02", "event": "failed login"},
        ],
    }

@app.post("/cases/", operation_id="create_case")
def create_case(case: CaseCreate):
    return {
        "status": "open",
        "title": case.title,
        "severity": case.severity,
        "context": case.context,
    }


# --- CVE Dummy (für Tests) ---------------------------------------------------
@app.get("/cve/{cve_id}", operation_id="cve_lookup")
def cve_lookup(cve_id: str):
    url = f"https://example.local/cve/{cve_id}"  # wird in Unit-Tests gemockt
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        data = r.json()
        vulns = data.get("vulnerabilities", []) if isinstance(data, dict) else []
        if not vulns:
            raise HTTPException(status_code=404, detail="CVE not found")
        return vulns[0]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"CVE lookup error: {e}")


# --- CVE LIVE (NVD API v2) ---------------------------------------------------
@app.get("/cve/live/{cve_id}", operation_id="cve_live")
def cve_live(cve_id: str):
    base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    url = f"{base}?cveId={cve_id}&noRejected"
    headers: Dict[str, str] = {"User-Agent": "soc-mcp/1.1"}
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key
    t0 = perf_counter()
    r = None
    try:
        r = requests.get(url, headers=headers, timeout=20)
        if r.status_code == 429:
            time.sleep(6)
            r = requests.get(url, headers=headers, timeout=20)
        r.raise_for_status()
        js = r.json()
        vulns = js.get("vulnerabilities", [])
        if not vulns:
            raise HTTPException(status_code=404, detail="CVE not found")
        item = vulns[0]
        cve = item.get("cve", {})

        metrics = item.get("metrics") or {}
        cvss_data = None
        base_sev = None
        vector = None

        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            arr = metrics.get(key) or []
            if not arr:
                continue
            m0 = arr[0]
            data = m0.get("cvssData") or {}
            cvss_data = data if data else None
            base_sev = m0.get("baseSeverity") or data.get("baseSeverity")
            vector = data.get("vectorString")
            break

        summary = {
            "id": cve.get("id"),
            "published": cve.get("published"),
            "lastModified": cve.get("lastModified"),
            "baseScore": (cvss_data or {}).get("baseScore"),
            "baseSeverity": base_sev,
            "vector": vector,
            "description": next(
                (d.get("value") for d in (cve.get("descriptions") or []) if d.get("lang") == "en"),
                None,
            ),
        }

        return {"summary": summary, "raw": item}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"CVE lookup failed: {e}")
    finally:
        dt = (perf_counter() - t0) * 1000.0
        status_code = getattr(r, "status_code", 500)
        try:
            log_action("http", {
                "method": "GET",
                "path": f"/cve/live/{cve_id}",
                "status": int(status_code),
                "duration_ms": round(dt, 2),
            })
        except Exception:
            pass


# --- Health ----------------------------------------------------------
@app.get("/_health/nvd", operation_id="nvd_health")
def nvd_health():
    test_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-3094&noRejected"
    headers: Dict[str, str] = {"User-Agent": "soc-mcp/1.1"}
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key
    try:
        r = requests.get(test_url, headers=headers, timeout=20)
        status_code = r.status_code
        if status_code == 200:
            js = r.json()
            ok = bool(js.get("vulnerabilities"))
            return {"status": "ok" if ok else "error", "http_status": status_code}
        msg = r.headers.get("message", "") or ""
        if status_code == 404 and "invalid apikey" in msg.lower():
            return {"status": "invalid_api_key", "http_status": status_code, "message": msg}
        if status_code == 429:
            return {"status": "rate_limited", "http_status": status_code}
        return {"status": "error", "http_status": status_code, "message": msg}
    except Exception as e:
        return {"status": "error", "http_status": None, "message": str(e)}

@app.get("/_health/taxii", operation_id="taxii_health")
def taxii_health():
    try:
        url = _enterprise_collection_url()
        r = requests.get(url, headers={"Accept": "application/taxii+json; version=2.1"}, timeout=20)
        r.raise_for_status()
        return {"status": "ok", "collection_url": url, "http_status": r.status_code}
    except HTTPException as he:
        return {"status": "error", "http_status": he.status_code, "detail": he.detail}
    except requests.HTTPError as e:
        return {"status": "error", "http_status": getattr(e.response, "status_code", None), "detail": str(e)}
    except Exception as e:
        return {"status": "error", "http_status": None, "detail": str(e)}


# --- VirusTotal ----------------------------------------------------
@app.get("/malware/{file_hash}", operation_id="malware_check")
def malware_check(file_hash: str):
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        raise HTTPException(status_code=400, detail="VIRUSTOTAL_API_KEY not set")
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    try:
        r = requests.get(url, headers=headers, timeout=15)
        r.raise_for_status()
        data = r.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0) or 0)
        verdict = "malicious" if malicious > 0 else "clean"
        return {"hash": file_hash, "verdict": verdict, "stats": stats, "source": "VirusTotal"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"VirusTotal error: {e}")


# --- Splunk Export (v2) + CSV-Mock --------------------------------------
def splunk_export(query: str, base: str, token: Optional[str] = None) -> Dict[str, Any]:
    headers: Dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    url = f"{base.rstrip('/')}/services/search/v2/jobs/export"
    resp = requests.post(
        url,
        data={"search": query, "output_mode": "json"},
        headers=headers,
        timeout=20,
    )
    resp.raise_for_status()
    return resp.json()

@lru_cache(maxsize=8)
def _load_csv_rows(path: str) -> List[Dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        return []
    with p.open("r", encoding="utf-8", newline="") as fh:
        return [dict(r) for r in csv.DictReader(fh)]

def _parse_kv_query(q: str) -> Dict[str, Any]:
    out = {"limit": 50, "dataset": None, "kv": {}}
    for tok in (q or "").split():
        if "=" in tok:
            k, v = tok.split("=", 1)
            if k.lower() == "dataset":
                out["dataset"] = v
            elif k.lower() == "limit":
                try:
                    out["limit"] = max(1, min(1000, int(v)))
                except Exception:
                    pass
            else:
                out["kv"][k] = v
    return out

def _filter_rows(rows: List[Dict[str, Any]], kv: Dict[str, str], limit: int) -> List[Dict[str, Any]]:
    def ok(r: Dict[str, Any]) -> bool:
        for k, v in kv.items():
            if k not in r or v.lower() not in str(r[k]).lower():
                return False
        return True
    out: List[Dict[str, Any]] = []
    for r in rows:
        if ok(r):
            out.append(r)
            if len(out) >= limit:
                break
    return out

def _pick(d: dict, *candidates: str) -> str:
    low = {k.lower(): v for k, v in d.items()}
    for cand in candidates:
        v = low.get(cand.lower())
        if v is not None:
            return str(v)
    return ""

@app.post("/splunk/export", operation_id="splunk_export")
def splunk_export_route(body: SplunkExportBody):
    # 1) CSV-Mock, wenn dataset=... und config.json gesetzt
    try:
        parsed = _parse_kv_query(body.query or "")
        ds = parsed.get("dataset")
        if ds and ds in DATASETS_CFG_SPLUNK:
            rows = _load_csv_rows(DATASETS_CFG_SPLUNK[ds])
            mapped = []
            for r in _filter_rows(rows, parsed["kv"], parsed["limit"]):
                mapped.append({
                    "_time": _pick(r, "deviceReceiptTime", "timestamp", "time", "date", "event time"),
                    "host":  _pick(r, "deviceHostName", "hostname", "host"),
                    "src_ip":  _pick(r, "src", "sourceAddress", "source ip", "src_ip", "s_ip"),
                    "dest_ip": _pick(r, "dst", "destinationAddress", "destination ip", "dest_ip", "d_ip"),
                    "action":  _pick(r, "action", "status", "decision", "log subtype"),
                    "dest_port": _pick(r, "dpt", "destinationPort", "dest_port", "dport", "destination port"),
                    "_raw": r
                })
            return {"query": body.query, "results": mapped, "source": f"mock:{ds}"}
    except Exception:
        # fällt zurück auf echten Export
        pass

    # 2) Echt: Splunk-Export REST v2
    try:
        js = splunk_export(body.query, body.base or "", body.token)
        return {"query": body.query, "results": js.get("results", js)}
    except requests.HTTPError as e:
        raise HTTPException(status_code=e.response.status_code, detail=f"Splunk error: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Splunk export error: {e}")


# --- Sentinel / Azure Monitor Logs ------------------------------------------
def sentinel_query(workspace_id: str, kql: str, token: str, timespan: str = "PT1H") -> Dict[str, Any]:
    if not token:
        raise HTTPException(status_code=400, detail="Missing Bearer token")
    url = f"https://api.loganalytics.azure.com/v1/workspaces/{workspace_id}/query"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    payload = {"query": kql, "timespan": timespan}
    r = requests.post(url, headers=headers, json=payload, timeout=25)
    r.raise_for_status()
    return r.json()

@app.post("/sentinel/query", operation_id="sentinel_query")
def sentinel_query_route(body: SentinelQueryBody):
    # 1) CSV-Mock: dataset=... im "KQL" verwenden
    try:
        kql = body.kql or ""
        parsed = _parse_kv_query(kql.replace("|", " "))
        ds = parsed.get("dataset")
        if ds and ds in DATASETS_CFG_SENTINEL:
            rows = _load_csv_rows(DATASETS_CFG_SENTINEL[ds])
            rows = _filter_rows(rows, parsed["kv"], parsed["limit"])
            # simple "project"-Unterstützung
            if "project" in kql.lower():
                after = kql.lower().split("project", 1)[1].strip()
                cols = [c.strip() for c in after.split()[0].split(",")]
                rows = [{c: r.get(c, "") for c in cols} for r in rows]
            return {"query": body.kql, "rows": rows, "source": f"mock:{ds}"}
    except Exception:
        pass

    # ---------- 2) Echt: Azure Monitor Logs --------------
    try:
        return sentinel_query(body.workspace_id, body.kql, body.token or "", body.timespan or "PT1H")
    except requests.HTTPError as e:
        raise HTTPException(status_code=e.response.status_code, detail=f"Sentinel error: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Sentinel query error: {e}")


# --- MCP-Tools registrieren -------------------------------------------
mcp.setup_server()


# --- Main -------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    host = CFG.get("server", {}).get("host", "127.0.0.1")
    port = int(CFG.get("server", {}).get("port", 8000))
    reload = bool(CFG.get("server", {}).get("reload", False))
    uvicorn.run(app, host=host, port=port, reload=reload)
