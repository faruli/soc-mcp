# SOC-MCP Server – Demo, Dashboard & Tests (Thesis)

Ein lokaler **SOC-Server** mit **Auto-Enrichment** (CVE/MITRE), **Mock-Integrationen** (Splunk/Sentinel via CSV), **VirusTotal-Beispiel** (EICAR) und einem **Security-Proxy Dashboard**.  
Ziel: Reproduzierbare, vorführbare Evaluierung in der Abschlussarbeit – mit kleinen, klaren Endpunkten und sichtbarer Audit/Alerts/Enrichment-UI.

---

## Inhaltsverzeichnis

- [Features](#features)
- [Verzeichnis & Datei-Referenz](#verzeichnis--datei-referenz)
- [Schnellstart](#schnellstart)
- [Server starten](#server-starten)
- [Dashboard benutzen](#dashboard-benutzen)
- [Beispieldaten einspeisen (CSV → Alerts)](#beispieldaten-einspeisen-csv--alerts)
- [VirusTotal/EICAR Demo & Abbildungen](#virustotaleicar-demo--abbildungen)
- [Konfiguration (`config.json`)](#konfiguration-configjson)
- [Umgebungsvariablen / `.env`](#umgebungsvariablen--env)
- [API-Endpunkte (Kurzreferenz)](#api-endpunkte-kurzreferenz)
- [Tests](#tests)
- [MCP / Claude Desktop](#mcp--claude-desktop)
- [Was nicht ins Repo gehört](#was-nicht-ins-repo-gehört)
- [Troubleshooting](#troubleshooting)
- [Hinweise für die Thesis (Screenshots & Repro)](#hinweise-für-die-thesis-screenshots--repro)

---

## Features

- **SOC-API (FastAPI, Port 8000):** Alerts, Enrichment, CVE/ATT&CK, VirusTotal, Splunk/Sentinel (Mock).
- **Auto-Enrichment:** CVE-Score & ATT&CK-Heuristik → Severity/Score + Audit-Event.
- **Security-Proxy & Dashboard (Port 8030):** Tabs **Audit**, **Alerts**, **Enrich** + VT-EICAR-Modal.
- **Mock-Integrationen:** CSV-Datasets für Splunk/Sentinel (deterministisch, keine Quoten/Secrets).
- **CSV-Pusher:** `push_csv_alerts.py` verwandelt Firewall-CSV-Zeilen in Alerts (→ `/alerts/ingest`).
- **Tests:** Pytest-Skeleton (HTTP, VT, Integrations-Smoke).

---

## Verzeichnis & Datei-Referenz

<details>
<summary><b>Projektbaum (aus Sicht des Repos)</b></summary>

soc_mcp/
├─ src/
│ ├─ soc_server.py
│ ├─ security_proxy.py
│ ├─ dashboard/
│ │ └─ index.html
│ ├─ utils/
│ │ └─ audit.py
│ ├─ data/
│ │ └─ attack_techniques.json
│ └─ logs/ # (Laufzeit) _audit.json, _alerts.json, _enrich.json
├─ scripts/
│ ├─ push_csv_alerts.py
│ ├─ demo.ps1
│ └─ demo_eicar.ps1
├─ data/
│ └─ samples/
│ └─ firewall/
│ └─ new_logs.csv
├─ docs/
│ ├─ assets/vt_eicar_raw.json
│ └─ fig/ # hier landen deine Screenshots
├─ tests/
│ ├─ test_soc_server.py
│ ├─ test_virustotal.py
│ └─ test_integrations.py
├─ config.json
├─ requirements.txt
├─ pytest.ini
└─ .gitignore

bash
Code kopieren
</details>

| Pfad | Typ | Zweck / Inhalt | Commit? |
|---|---|---|---|
| `src/soc_server.py` | Python | **Haupt-API** (Alerts, Enrichment, CVE/ATT&CK, Splunk/Sentinel-Mock, VT) | ✔️ |
| `src/security_proxy.py` | Python | **Security-Proxy** + Dashboard-Feeds (`/_audit.json`, `/_alerts.json`, `/_enrich.json`) | ✔️ |
| `src/dashboard/index.html` | HTML/JS | **Dashboard** (Tabs, Auto-Refresh, Filter, VT-Modal) | ✔️ |
| `src/utils/audit.py` | Python | JSONL-Audit-Writer | ✔️ |
| `src/data/attack_techniques.json` | JSON | MITRE ATT&CK Offline-Cache | ✔️ |
| `src/logs/_*.json` | JSONL | **Laufzeit-Logs** (Audit/Alerts/Enrich) | ❌ |
| `scripts/push_csv_alerts.py` | Python | CSV → Alerts (POST `/alerts/ingest`) | ✔️ |
| `scripts/demo.ps1` | PS | Mini-Demo (typische Endpunkte) | ✔️ |
| `scripts/demo_eicar.ps1` | PS | EICAR/VT-Beispiel & JSON-Export | ✔️ |
| `data/samples/firewall/new_logs.csv` | CSV | Beispiel-Firewall-Logs | optional |
| `docs/assets/vt_eicar_raw.json` | JSON | Roh-Dump VT-EICAR (für Abbildung/Tabelle) | ✔️ |
| `tests/*` | Pytest | Kern- und Integrations-Smoke | ✔️ |
| `config.json` | JSON | Ports, Dashboard-Pfad, Dataset-Pfade (Mocks) | ✔️ |
| `.env` | Text | Secrets/Flags (VT/NVD Keys) | ❌ |

> **Hinweis:** Die Laufzeit-Logs und `.env` sind via `.gitignore` ausgeschlossen.

---

## Schnellstart

```# 1) Virtuelle Umgebung
python -m venv .venv

# 2) Aktivieren
# Windows:
.\.venv\Scripts\activate
# macOS/Linux:
# source .venv/bin/activate

# 3) Abhängigkeiten
pip install -r requirements.txt

# 4) .env anlegen (im Projektroot oder unter src/.env), z. B.:
# SOC_ENRICH=1
# (optional) VIRUSTOTAL_API_KEY=...
# (optional) NVD_API_KEY=...
Server starten
Terminal A – API (Port 8000):

Code kopieren
python src/soc_server.py
Terminal B – Proxy & Dashboard (Port 8030):

Code kopieren
python src/security_proxy.py
Dashboard öffnen:
http://127.0.0.1:8030/dashboard/

Dashboard benutzen
Feed-Schalter: Audit · Alerts · Enrich

Auto-Refresh: 5s / 10s / 30s / aus

Suche: filtert die Tabellenzeilen im aktiven Feed

VT-EICAR Modal: zeigt kompaktes JSON & Kernfelder

Feeds:

Audit: HTTP-Events (Methode, Pfad, Status, Latenz)

Alerts: Roh-Alerts (CSV-Push oder manuelle POSTs)

Enrich: Ergebnisse Auto-Anreicherung (CVE/MITRE, Score, Severity)

Beispieldaten einspeisen (CSV → Alerts)
CSV: data/samples/firewall/new_logs.csv (Fortinet-ähnliche Spalten)

PowerShell (Windows):

Code kopieren
python scripts\push_csv_alerts.py `
  --csv data\samples\firewall\new_logs.csv `
  --col-ts "Time" --col-src "Src IP" --col-dst "Dst IP" --col-dpt "Dst port" `
  --col-action "Log subtype" --col-message "Message" `
  --limit 25 --sleep 1
Nur „blocked“-Events:

Code kopieren
python scripts\push_csv_alerts.py `
  --csv data\samples\firewall\new_logs.csv `
  --col-ts "Time" --col-src "Src IP" --col-dst "Dst IP" --col-dpt "Dst port" `
  --col-action "Log subtype" --col-message "Message" `
  --only-action blocked --limit 20
Danach erscheinen Alerts → kurz darauf Enrich im Dashboard.

VirusTotal/EICAR Demo & Abbildungen
Für Abbildung 5-5 (VT-Ausschnitt) und Tabelle 5-2 (wichtige VT-Felder).

.env setzen:

Code kopieren
VIRUSTOTAL_API_KEY=dein-key
SOC_ENRICH=1
Test-Alert senden (PowerShell):

Code kopieren
$alert = @{
  AlertName="FW: Allowed 8.8.8.8:53"; Severity="low";
  Description="Allowed 192.168.1.10 -> 8.8.8.8:53 | UDP";
  Techniques=@("T1046");
  Entities=@{ Host="8.8.8.8"; Account="" };
  Evidence=@{ Message="Allowed 192.168.1.10 -> 8.8.8.8:53"; When=(Get-Date).ToString("o") }
} | ConvertTo-Json -Depth 6

Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/alerts/ingest `
  -ContentType "application/json" -Body $alert
Abbildung 5-5 erstellen:

Dashboard → VT-EICAR Modal öffnen

Screenshot speichern unter docs/fig/abb-5-5_vt_eicar.png

Werte aus docs/assets/vt_eicar_raw.json entnehmen:
last_analysis_stats.malicious, last_analysis_stats.undetected, last_analysis_date (Unix → UTC im Text nennen)

Konfiguration (config.json)
Code kopieren
{
  "server": { "host": "127.0.0.1", "port": 8000, "reload": false },
  "proxy":  { "host": "127.0.0.1", "port": 8010, "reload": false },
  "resources": {
    "dashboard": "src/dashboard/index.html",
    "log_file": "src/logs/_audit.json"
  },
  "datasets": {
    "splunk":   { "fortinet_cef": "data/samples/firewall/new_logs.csv" },
    "sentinel": { "fortinet_cef": "data/samples/firewall/new_logs.csv" }
  }
}
resources.dashboard darf Datei oder Ordner sein.

datasets.* aktivierst du, indem die Query dataset=<key> enthält.

Umgebungsvariablen / .env
Code kopieren
# Enrichment
SOC_ENRICH=1
SOC_ENRICH_OFFLINE=0
SOC_ENRICH_MAX_CVES=3

# Externe APIs (optional)
NVD_API_KEY=...
VIRUSTOTAL_API_KEY=...

# ggf. Proxy
# HTTP_PROXY=...
# HTTPS_PROXY=...
Wichtig: .env niemals committen.

API-Endpunkte (Kurzreferenz)
POST /alerts/ingest – nimmt Alerts an; antwortet 202, Enrichment asynchron

GET /attack/{tech_id} – lokaler ATT&CK-Cache (z. B. T1059.001)

GET /attack/live/{tech_id} – MITRE ATT&CK (TAXII 2.1)

GET /cve/live/{cve_id} – NVD API v2 (?cveId=…)

GET /malware/{hash} – VirusTotal v3 (Dateiobjekt)

POST /splunk/export – Echt-Export oder CSV-Mock (Query enthält dataset=)

POST /sentinel/query – Echt-KQL oder CSV-Mock (KQL enthält dataset=)

GET /_health/nvd · /_health/taxii – Health-Checks

GET /_audit.json · /_alerts.json · /_enrich.json – Feeds fürs Dashboard

MCP über FastApiMCP (HTTP-Tools)

Tests
Code kopieren
pytest -q
Läuft auch ohne echte Keys (dann Struktur/Fehlerpfade).

Optional: VCR/pytest-recording für eingefrorene Live-Antworten.

MCP / Claude Desktop
Beide Server starten → Claude Desktop öffnen → lokalen HTTP-MCP verbinden.

Tools wie health, get_audit oder eigene API-Calls stehen dem LLM zur Verfügung (siehe Kapitel 5.6 in der Arbeit).

Was nicht ins Repo gehört
.env, src/logs/_*.json, .venv/, __pycache__/, node_modules/

Große/urheberrechtlich heikle Datasets

Troubleshooting
Dashboard leer?
Läuft security_proxy.py (8030)? Liefert http://127.0.0.1:8030/_audit.json Daten?
CSV-Pusher gesendet? → Tab Alerts/Enrich prüfen.

VirusTotal 400/401?
VIRUSTOTAL_API_KEY gesetzt? Rate-Limit?

NVD 429?
Später erneut (Retry/Backoff ist aktiv).

ImportError src.utils.audit?
audit.py liegt unter src/utils/. Alte Dubletten löschen.

Hinweise für die Thesis (Screenshots & Repro)
Ablage:

Screenshots → docs/fig/ (z. B. abb-5-3_endpoints.png)

VT-Rohdaten → docs/assets/vt_eicar_raw.json (liegt vor)

Empfohlene Motive:

Audit-Tab mit eingehenden Requests (zeigt asynchronen Ablauf)

Alerts-Tab nach CSV-Push

Enrich-Tab mit Severity/Score + CVE/MITRE

Health-Checks (NVD/TAXII)

Repro-Hinweise im Text:
Start-Kommandos, Pfade, Beispiel-POST, dataset=…-Mocks, gesetzte Variablen (ohne Secrets).
