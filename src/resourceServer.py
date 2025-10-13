# -*- coding: utf-8 -*-
"""
resourceServer.py - erweiterter Ressourcenbasierter MCP-Server (STDIO/JSON-RPC 2.0)

READ-only Ressourcen:
 - data://docs/{id}
 - data://docs/index?offset={offset}&limit={limit}&kind={kind}
 - data://docs/all

Komfort-Tools (für UI):
 - list_docs(kind: str | None, limit: int)
 - get_doc(id: int)
"""

from __future__ import annotations
import sys
from typing import Any
from pydantic import BaseModel, field_validator

# robuster Import für FastMCP / Context
try:
    from mcp.server.fastmcp import FastMCP, Context
except Exception:
    try:
        from fastmcp import FastMCP, Context
    except Exception as e:
        raise ImportError(
            "FastMCP konnte nicht importiert werden. Versuche: pip install mcp oder passe PYTHONPATH an. Ursprungsfehler: "
            + str(e)
        )

mcp = FastMCP(name="ResourceServer")


class Doc(BaseModel):
    id: int
    kind: str      # "note" | "policy" | "spec"
    title: str
    body: str

    @field_validator("kind")
    @classmethod
    def validate_kind(cls, v: str) -> str:
        allowed = {"note", "policy", "spec"}
        if v not in allowed:
            raise ValueError(f"kind must be one of {sorted(allowed)}")
        return v


# Dummy-Daten - 20+ Einträge
STORE: list[Doc] = [
    Doc(id=1, kind="note", title="Willkommen", body="Hallo MCP!"),
    Doc(id=2, kind="policy", title="Sicherheitsrichtlinie", body="Consent erforderlich für Schreibzugriffe."),
    Doc(id=3, kind="spec", title="Schnittstellen", body="resources/list, resources/read, tools/list"),
]

KINDS = ["note", "policy", "spec"]
for i in range(4, 25):
    kind = KINDS[(i - 1) % len(KINDS)]
    STORE.append(
        Doc(
            id=i,
            kind=kind,
            title=f"Demo-{kind}-{i}",
            body=(
                f"Dies ist ein Dummy-Dokument {i} vom Typ '{kind}'. "
                "Es dient zum Testen von Pagination (offset/limit) und Filtern (kind)."
            ),
        )
    )


# ----------------- Ressourcen (READ-only) -----------------

@mcp.resource(
    "data://docs/{id}",
    name="Einzelnes Dokument",
    description="Liest ein Dokument anhand seiner ID.",
    mime_type="application/json",
)
def read_doc(id: str) -> dict[str, Any]:
    """data://docs/{id} - id als String (aus URL)"""
    rid = int(id)
    for d in STORE:
        if d.id == rid:
            return d.model_dump()
    raise ValueError(f"document id={rid} not found")


@mcp.resource(
    "data://docs/index?offset={offset}&limit={limit}&kind={kind}",
    name="Dokumentenindex",
    description="Listet Dokumente mit optionalem Filter (kind) und Pagination.",
    mime_type="application/json",
)
def docs_index(offset: str = "0", limit: str = "10", kind: str | None = None) -> dict[str, Any]:
    """offset/limit kommen als Strings aus der URL; kind optional"""
    off = max(int(offset), 0)
    lim = max(min(int(limit), 200), 1)
    data = STORE if not kind else [d for d in STORE if d.kind == kind]
    window = data[off: off + lim]
    return {
        "total": len(data),
        "offset": off,
        "limit": lim,
        "items": [d.model_dump() for d in window],
    }


@mcp.resource(
    "data://docs/all",
    name="Alle Dokumente (kleine Datasets)",
    description="Gibt das komplette Demo-Dataset zurück (nur für kleine Mengen).",
    mime_type="application/json",
)
def all_docs() -> list[dict[str, Any]]:
    return [d.model_dump() for d in STORE]


# ----------------- Komfort-Tools (sichtbar in UI) -----------------

@mcp.tool()
def list_docs(kind: str | None = None, limit: int = 10) -> dict[str, Any]:
    """Hilfs-Tool: listet Dokumente (wie docs_index)."""
    data = STORE if not kind else [d for d in STORE if d.kind == kind]
    limit = max(1, min(limit, 200))
    return {"total": len(data), "items": [d.model_dump() for d in data[:limit]]}


@mcp.tool()
def get_doc(id: int) -> dict[str, Any]:
    """Hilfs-Tool: liest ein Dokument per ID (Tool-Form)."""
    for d in STORE:
        if d.id == id:
            return {"doc": d.model_dump()}
    raise ValueError(f"document id={id} not found")


# ----------------- Start (STDIO) -----------------

if __name__ == "__main__":

    print("ResourceServer: starting (stderr).", file=sys.stderr)
   
    mcp.run()
