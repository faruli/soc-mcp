from time import perf_counter
from fastapi.testclient import TestClient

# Wichtig: Import der App
from src.soc_server import app
import src.soc_server as srv  # für monkeypatch auf requests

# Audit-Logger importieren
from src.utils.audit import log_action

client = TestClient(app)


def test_attack_lookup_ok():
    t0 = perf_counter()
    resp = client.get("/attack/T1059")
    dt = (perf_counter() - t0) * 1000.0
    # Audit-Eintrag direkt nach dem Request+ 
    log_action("test", {
        "method": "GET",
        "path": "/attack/T1059",
        "status": resp.status_code,
        "duration_ms": round(dt, 2),
    })
    assert resp.status_code == 200
    js = resp.json()
    assert js["technique_id"] == "T1059"
    assert "name" in js


def test_splunk_search_mock():
    t0 = perf_counter()
    resp = client.post("/splunk/search", json={"query": "failed login"})
    dt = (perf_counter() - t0) * 1000.0
    log_action("test", {
        "method": "POST",
        "path": "/splunk/search",
        "status": resp.status_code,
        "duration_ms": round(dt, 2),
    })
    assert resp.status_code == 200
    js = resp.json()
    assert js["query"] == "failed login"
    assert isinstance(js["results"], list)


def test_create_case():
    payload = {"title": "Suspicious Logins", "severity": "high", "context": {"host": "srv01"}}
    t0 = perf_counter()
    resp = client.post("/cases/", json=payload)
    dt = (perf_counter() - t0) * 1000.0
    log_action("test", {
        "method": "POST",
        "path": "/cases/",
        "status": resp.status_code,
        "duration_ms": round(dt, 2),
    })
    assert resp.status_code == 200
    js = resp.json()
    assert js["status"] == "open"
    assert js["title"] == "Suspicious Logins"


def test_cve_lookup_handles_notfound(monkeypatch):
    # Externen Call mocken
    class FakeResp:
        status_code = 200
        def raise_for_status(self): pass
        def json(self): return {"vulnerabilities": []}
    monkeypatch.setattr(srv.requests, "get", lambda *a, **k: FakeResp())

    t0 = perf_counter()
    resp = client.get("/cve/CVE-2099-0000")
    dt = (perf_counter() - t0) * 1000.0
    log_action("test", {
        "method": "GET",
        "path": "/cve/CVE-2099-0000",
        "status": resp.status_code,
        "duration_ms": round(dt, 2),
    })
    assert resp.status_code == 404  # keine Items => 404 


def test_virustotal_check_mock(monkeypatch):
    # VT-Key per Env setzen damit die Route nicht abbricht
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "dummy")

    class FakeVT:
        status_code = 200
        def raise_for_status(self): pass
        def json(self):
            return {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 0, "undetected": 70}
                    }
                }
            }
    monkeypatch.setattr(srv.requests, "get", lambda *a, **k: FakeVT())

    t0 = perf_counter()
    resp = client.get("/malware/44d88612fea8a8f36de82e1278abb02f")
    dt = (perf_counter() - t0) * 1000.0
    log_action("test", {
        "method": "GET",
        "path": "/malware/44d88612fea8a8f36de82e1278abb02f",
        "status": resp.status_code,
        "duration_ms": round(dt, 2),
    })
    assert resp.status_code == 200
    js = resp.json()
    assert js["verdict"] in ("clean", "malicious")
    assert js["source"] == "VirusTotal"
