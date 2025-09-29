#!/usr/bin/env python3
"""
Robuster VT-Check:
- Sucht .env automatisch (find_dotenv) – bevorzugt im selben Ordner wie diese Datei.
- Prüft, ob VIRUSTOTAL_API_KEY wirklich geladen ist.
- Fragt EICAR-Hash bei VT ab und zeigt kompakte Infos.
"""

import os
import sys
from pathlib import Path

import requests

# --- .env robust laden ---
try:
    from dotenv import load_dotenv, find_dotenv
except ImportError:
    print("ERROR: python-dotenv ist nicht installiert. Bitte ausführen:\n  pip install python-dotenv")
    sys.exit(2)

# 1) Versuche: .env neben dieser Datei (z. B. src/.env)
candidate = Path(__file__).with_name(".env")
dotenv_path = None
if candidate.exists():
    dotenv_path = str(candidate.resolve())
else:
    # 2) Falls nicht gefunden: automatisch suchen (aufwärtsgehend)
    #    usecwd=True berücksichtigt das aktuelle Arbeitsverzeichnis (VSCode/Terminal)
    found = find_dotenv(filename=".env", usecwd=True)
    if found:
        dotenv_path = found

if not dotenv_path:
    print("ERROR: Keine .env gefunden. Erwartet z. B.: src/.env")
    sys.exit(2)

print("Lade .env von:", dotenv_path)
load_dotenv(dotenv_path=dotenv_path, override=True)

# --- Key lesen & validieren ---
VT_KEY = os.getenv("VIRUSTOTAL_API_KEY")
if not VT_KEY:
    print("ERROR: VIRUSTOTAL_API_KEY ist nicht gesetzt bzw. leer.")
    print("Bitte prüfe Inhalt deiner .env:\n  VIRUSTOTAL_API_KEY=dein_api_key_ohne_Anfuehrungszeichen\n")
    sys.exit(2)

# --- VT-Request ---
TEST_HASH = "44d88612fea8a8f36de82e1278abb02f"  # EICAR
url = f"https://www.virustotal.com/api/v3/files/{TEST_HASH}"
headers = {"x-apikey": VT_KEY}

def main():
    try:
        resp = requests.get(url, headers=headers, timeout=15)
    except requests.RequestException as e:
        print("Request-Fehler:", e)
        sys.exit(3)

    print("HTTP-Status:", resp.status_code)
    if resp.status_code == 200:
        j = resp.json()
        attrs = j.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        print("Ergebnis (kompakt):")
        print("  malicious:", stats.get("malicious"))
        print("  undetected:", stats.get("undetected"))
        print("  last_analysis_date:", attrs.get("last_analysis_date"))
    elif resp.status_code == 404:
        print("Hash nicht in VirusTotal gefunden (404).")
    elif resp.status_code in (401, 403):
        print("Authentifizierungsfehler (401/403). Prüfe den API-Key in src/.env.")
    else:
        print("Unerwarteter Status. Body (erste 300 Zeichen):")
        print(resp.text[:300])

if __name__ == "__main__":
    main()
