from fastapi.testclient import TestClient
from src.soc_server import app
import src.soc_server as srv

client = TestClient(app)

def test_splunk_export_route(monkeypatch):
    class FakeResp:
        status_code = 200
        def raise_for_status(self): pass
        def json(self):
            return {"results": [
                {"_time":"2025-09-14T10:00:00Z","host":"srv01","event":"failed login"},
                {"_time":"2025-09-14T10:05:00Z","host":"srv02","event":"failed login"},
            ]}
    monkeypatch.setattr(srv.requests, "post", lambda *a, **k: FakeResp())
    r = client.post("/splunk/export", json={
        "query": "search index=auth failed login",
        "base": "https://splunk.local:8089",
        "token": "dummy"
    })
    assert r.status_code == 200
    assert r.json()["results"][0]["event"] == "failed login"

def test_sentinel_query_route(monkeypatch):
    class FakeResp:
        status_code = 200
        def raise_for_status(self): pass
        def json(self):
            return {"tables":[
                {"name":"PrimaryResult",
                 "columns":[{"name":"TimeGenerated"},{"name":"Computer"}],
                 "rows":[["2025-09-14T10:00:00Z","srv01"]]}
            ]}
    monkeypatch.setattr(srv.requests, "post", lambda *a, **k: FakeResp())
    r = client.post("/sentinel/query", json={
        "workspace_id": "ws-1234",
        "kql": "SecurityEvent | take 1",
        "token": "dummy",
        "timespan": "PT1H"
    })
    assert r.status_code == 200
    assert r.json()["tables"][0]["rows"][0][1] == "srv01"

