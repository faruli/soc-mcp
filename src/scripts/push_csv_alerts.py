#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
push_csv_alerts.py — liest Firewall-CSV und sendet Alerts an /alerts/ingest

Beispiel (PowerShell, Spalten ggf. anpassen):
  python src/scripts/push_csv_alerts.py `
    --csv src/data/samples/firewall/new_logs.csv `
    --col-ts "Time" --col-src "Src IP" --col-dst "Dst IP" `
    --col-dpt "Dst port" --col-action "Log subtype" --col-message "Message" `
    --limit 25 --sleep 1
"""
import argparse
import csv
import sys
import time
from pathlib import Path

import requests
from dateutil import parser as dtp

DEFAULT_BASE = "http://127.0.0.1:8000"


def pick(row: dict, prefer: list[str], fallback: list[str]) -> str:
    """Hole den ersten passenden Wert (case-insensitive) aus prefer+fallback."""
    low = {k.lower(): v for k, v in row.items()}
    for c in prefer + fallback:
        v = low.get(c.lower())
        if v is not None:
            return str(v)
    return ""


def as_iso(ts: str) -> str:
    """Timestamp robust in ISO 8601 wandeln (sonst Rohwert zurückgeben)."""
    ts = (ts or "").strip()
    if not ts:
        return ""
    try:
        return dtp.parse(ts).astimezone().isoformat()
    except Exception:
        return ts


def map_techniques_by_port(port: str) -> list[str]:
    """Mini-Heuristik für MITRE-Techniken anhand Zielport (Demo)."""
    try:
        p = int(str(port).strip())
    except Exception:
        return []
    if p == 3389:
        return ["T1021.001"]  # RDP
    if p == 22:
        return ["T1021.004"]  # SSH
    if p == 445:
        return ["T1021.002"]  # SMB
    return []


def severity_from_action(action: str, dpt: str = "") -> str:
    """Schweregrad grob aus Aktion/Port ableiten (Demo-freundlich)."""
    a = (action or "").lower()
    if "deny" in a or "block" in a or "drop" in a or "dropped" in a:
        return "Medium"
    # leichte Anhebung für sensible Admin-Ports
    try:
        p = int(str(dpt).strip())
        if p in (22, 3389, 445):
            return "Medium"
    except Exception:
        pass
    return "Low"


def read_csv(csv_path: Path, delimiter: str = "", encoding: str = "utf-8-sig") -> list[dict]:
    """CSV laden, Delimiter optional raten (Fallback ',')."""
    text = csv_path.read_text(encoding=encoding, errors="replace")
    if not delimiter:
        try:
            sample = "\n".join(text.splitlines()[:10]) + "\n"
            dialect = csv.Sniffer().sniff(sample)
            delimiter = dialect.delimiter
        except Exception:
            delimiter = ","
    return list(csv.DictReader(text.splitlines(), delimiter=delimiter))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True, help="Pfad zur CSV")
    ap.add_argument("--base-url", default=DEFAULT_BASE, help=f"Basis-URL des SOC-Servers (Default: {DEFAULT_BASE})")
    ap.add_argument("--limit", type=int, default=25, help="Max. Alerts senden")
    ap.add_argument("--sleep", type=float, default=1.0, help="Sekunden Pause zwischen Alerts")
    ap.add_argument("--only-action", default="", help="Nur Zeilen mit Aktion (contains, z. B. 'blocked')")
    ap.add_argument("--delimiter", default="", help="CSV-Delimiter erzwingen, z. B. ';' oder ','")
    ap.add_argument("--encoding", default="utf-8-sig", help="Encoding (Default: utf-8-sig)")
    ap.add_argument("--debug", action="store_true", help="Nur Header + 3 Beispiel-Mappings zeigen, nichts senden")
    # Mapping-Flags
    ap.add_argument("--col-ts", default="", help="Spalte Zeitstempel")
    ap.add_argument("--col-src", default="", help="Spalte Source IP")
    ap.add_argument("--col-dst", default="", help="Spalte Destination IP")
    ap.add_argument("--col-dpt", default="", help="Spalte Destination Port")
    ap.add_argument("--col-action", default="", help="Spalte Aktion/Status")
    ap.add_argument("--col-message", default="", help="Spalte Nachricht/Message")
    args = ap.parse_args()

    csv_path = Path(args.csv)
    if not csv_path.exists():
        print(f"[!] CSV nicht gefunden: {csv_path}", file=sys.stderr)
        sys.exit(1)

    try:
        rows = read_csv(csv_path, delimiter=args.delimiter, encoding=args.encoding)
    except Exception as e:
        print(f"[!] CSV-Parsing-Fehler: {e}", file=sys.stderr)
        sys.exit(2)

    if not rows:
        print("[!] CSV enthält keine Zeilen.", file=sys.stderr)
        sys.exit(3)

    # Fallback-Kandidaten (weit gefasst)
    FB_TS = ["devicereceipttime", "timestamp", "time", "date", "event time"]
    FB_SRC = ["src", "sourceaddress", "source ip", "src_ip", "source_ip", "s_ip"]
    FB_DST = ["dst", "destinationaddress", "destination ip", "dest_ip", "destination_ip", "d_ip"]
    FB_DPT = ["dpt", "destinationport", "dest_port", "dport", "destination port"]
    FB_ACT = ["action", "status", "decision", "log subtype", "event type", "rule action"]
    FB_MSG = ["message", "msg", "rule name", "rule", "event", "description"]
    # neue Fallbacks
    FB_RULE = ["firewall rule name", "rule name", "firewall rule"]
    FB_NAT = ["nat rule name", "nat rule"]
    FB_PROTO = ["protocol", "proto"]

    # User-Prioritäten
    prefer_ts = [args.col_ts] if args.col_ts else []
    prefer_src = [args.col_src] if args.col_src else []
    prefer_dst = [args.col_dst] if args.col_dst else []
    prefer_dpt = [args.col_dpt] if args.col_dpt else []
    prefer_act = [args.col_action] if args.col_action else []
    prefer_msg = [args.col_message] if args.col_message else []

    def build_alert(row: dict) -> dict:
        # ------- HIER dein gewünschter Block (voll integriert) -------
        ts = pick(row, prefer_ts, FB_TS)
        src = pick(row, prefer_src, FB_SRC)
        dst = pick(row, prefer_dst, FB_DST)
        dpt = pick(row, prefer_dpt, FB_DPT)
        act = pick(row, prefer_act, FB_ACT)
        msg = pick(row, prefer_msg, FB_MSG)

        # Fallback, wenn Message leer
        if not msg:
            bits = []
            rule = pick(row, [], FB_RULE)
            nat = pick(row, [], FB_NAT)
            proto = pick(row, [], FB_PROTO)
            if rule:
                bits.append(f"rule={rule}")
            if nat:
                bits.append(f"nat={nat}")
            if proto:
                bits.append(proto)
            msg = " ".join(bits)

        techs = map_techniques_by_port(dpt)

        # Hübsche Description ohne überflüssiges " | "
        core = f"{(act or '').strip()} {(src or '').strip()} -> {(dst or '').strip()}:{(dpt or '').strip()}".strip()
        desc = f"{core} | {msg}".strip() if msg else core

        name = f"FW: {(act or 'event').strip()} {(dst or '').strip()}:{(dpt or '').strip()}".strip().rstrip(":")
        return {
            "AlertName": name,
            "Severity": severity_from_action(act, dpt),
            "Description": desc,
            "Techniques": techs,
            "Entities": {"Host": dst, "Account": ""},
            "Evidence": {"Message": desc, "When": as_iso(ts)},
        }
        # -------------------------------------------------------------

    # Debug-Vorschau
    if args.debug:
        print("[DEBUG] Header:", ", ".join(rows[0].keys()))
        for i, r in enumerate(rows[:3], 1):
            a = build_alert(r)
            print(f"[DEBUG] Beispiel {i}:", a["Description"])
        return

    uri = f"{args.base_url.rstrip('/')}/alerts/ingest"
    sent = 0
    for r in rows:
        if sent >= args.limit:
            break
        act_val = pick(r, prefer_act, FB_ACT)
        if args.only_action and args.only_action.lower() not in (act_val or "").lower():
            continue
        alert = build_alert(r)
        try:
            resp = requests.post(uri, json=alert, timeout=10)
            resp.raise_for_status()
            print(f"[{alert['Evidence']['When'] or '-'}] {alert['Description']}")
            sent += 1
            time.sleep(max(0.0, args.sleep))
        except Exception as e:
            print(f"[!] Fehler beim Senden: {e}", file=sys.stderr)

    print(f"\n[*] Fertig: {sent} Alerts gesendet an {uri}")


if __name__ == "__main__":
    main()
