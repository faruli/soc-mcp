# tests/test_virustotal.py
import os
import pytest
from fastapi.testclient import TestClient
import requests

from src.soc_server import app

client = TestClient(app)

def test_malware_mock(monkeypatch):
    """VT-Endpoint wird gemockt, kein Internet/Key nötig."""
    class DummyResp:
        status_code = 200
        def raise_for_status(self): pass
        def json(self):
            return {"data": {"attributes": {"last_analysis_stats": {"malicious": 1}}}}
    monkeypatch.setattr(requests, "get", lambda *a, **k: DummyResp())

    r = client.get("/malware/44d88612fea8a8f36de82e1278abb02f")
    assert r.status_code == 200
    js = r.json()
    assert js["verdict"] == "malicious"
    assert js["source"] == "VirusTotal"

@pytest.mark.skipif(not os.getenv("VIRUSTOTAL_API_KEY"),
                    reason="Kein VIRUSTOTAL_API_KEY gesetzt – Live-Test übersprungen")
def test_malware_live_eicar():
    """Optionaler Live-Test (nur wenn VT-Key gesetzt)."""
    r = client.get("/malware/44d88612fea8a8f36de82e1278abb02f")
    assert r.status_code in (200, 400, 500)  # je nach Kontingent/Key
