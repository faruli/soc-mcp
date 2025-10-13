# toolServer.py - schlanker MCP-Tool-Server (Python, FastMCP, STDIO)
from __future__ import annotations

import sys
import json
import os
from pathlib import Path
from typing import Optional, List, Dict, Any

# Robuster Import: erst das namespaced package (mcp.server.fastmcp), dann fallback fastmcp.
try:
    from mcp.server.fastmcp import FastMCP, Context
except Exception:
    from fastmcp import FastMCP, Context

# ---------------- Konfiguration laden ----------------

DEFAULT_CFG = {
    "allowedHosts": ["api.github.com"],
    "httpTimeoutMs": 15_000,
    "allowedPaths": []
}

def load_cfg() -> dict:
    path = os.environ.get("CONFIG_PATH")
    cfg_path = Path(path) if path else Path(__file__).with_name("config.json")
    cfg = DEFAULT_CFG.copy()
    try:
        if cfg_path.exists():
            data = json.loads(cfg_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                cfg.update(data)
    except Exception:
        pass
    if not isinstance(cfg.get("allowedHosts"), list):
        cfg["allowedHosts"] = []
    if not isinstance(cfg.get("allowedPaths"), list):
        cfg["allowedPaths"] = []
    try:
        cfg["httpTimeoutMs"] = int(cfg.get("httpTimeoutMs", 15_000))
    except Exception:
        cfg["httpTimeoutMs"] = 15_000
    return cfg

CFG = load_cfg()

def _norm(p: Path) -> str:
    s = str(p.resolve())
    return s.casefold() if os.name == "nt" else s

def _allowed_path(target: Path) -> bool:
    if not CFG["allowedPaths"]:
        return False
    t = _norm(target)
    for root in CFG["allowedPaths"]:
        try:
            r = _norm(Path(root))
            if t == r or t.startswith(r + os.sep):
                return True
        except Exception:
            continue
    return False

def _host_allowed(url: str) -> bool:
    try:
        from urllib.parse import urlparse
        h = (urlparse(url).hostname or "").lower()
        return "*" in CFG["allowedHosts"] or h in [x.lower() for x in CFG["allowedHosts"]]
    except Exception:
        return False

# ---------------- MCP-Server & Tools ----------------

mcp = FastMCP("python-toolbox")  # name

@mcp.tool()
def ping() -> dict:
    from datetime import datetime, timezone
    return {"ok": True, "server": "python-toolbox", "time": datetime.now(timezone.utc).isoformat()}

@mcp.tool()
async def http_get(url: str, headers: Optional[dict] = None) -> dict:
    """HTTP GET zu erlaubten Hosts. Gibt Status, Content-Type und Body (Text) zurück."""
    if not _host_allowed(url):
        raise ValueError(f"Host nicht erlaubt. allowedHosts={CFG['allowedHosts'] or '(leer)'}")
    import aiohttp
    timeout = aiohttp.ClientTimeout(total=CFG["httpTimeoutMs"] / 1000)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(url, headers=headers or {}) as resp:
            body = await resp.text()
            return {"status": resp.status, "contentType": resp.headers.get("Content-Type", ""), "body": body}

@mcp.tool()
def read_text_file(file_path: str, max_bytes: int = 500_000) -> str:
    target = Path(file_path).resolve()
    if not _allowed_path(target):
        raise ValueError("Pfad nicht erlaubt – allowedPaths in config.json setzen.")
    data = target.read_bytes()
    return data[:max_bytes].decode("utf-8", errors="replace")

@mcp.tool()
def list_dir(dir_path: str) -> List[str]:
    target = Path(dir_path).resolve()
    if not _allowed_path(target):
        raise ValueError("Pfad nicht erlaubt – allowedPaths in config.json setzen.")
    return sorted(p.name for p in target.iterdir())

@mcp.tool()
async def process_data(data_uri: str, ctx: Context) -> dict:
    await ctx.info(f"Processing {data_uri} …")
    resource = await ctx.read_resource(data_uri)
    await ctx.report_progress(50, 100)
    return {"length": len(resource)}

# ---------------- Start (STDIO) ----------------

if __name__ == "__main__":
    print("ToolServer: starting (stderr).", file=sys.stderr)
    mcp.run()
