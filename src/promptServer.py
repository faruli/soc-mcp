from mcp.server.fastmcp import FastMCP, Context

mcp = FastMCP("python-toolbox")  # kein version-Argument

@mcp.prompt()  # Klammern!
def summarize_text(topic: str, max_words: int = 120) -> str:
    """Fasse das Thema prägnant zusammen (max. Wörterzahl). Gibt 3-5 Kernaussagen."""
    return (
        f"Fasse das Thema prägnant zusammen:\n\n"
        f"THEMA: {topic}\n- Max. {max_words} Wörter\n- 3-5 Kernaussagen als Liste."
    )

@mcp.prompt()
def code_review(lang: str, snippet: str) -> str:
    return (
        f"Bitte reviewe folgenden {lang}-Code:\n\n```{lang}\n{snippet}\n```\n"
        f"Kriterien: Korrektheit, Lesbarkeit, Robustheit, Fehlerbehandlung, Tests."
    )

@mcp.prompt()
def bug_fix_request(error: str, context: str | None = None) -> str:
    ctx = f"\nKONTEXT:\n{context}\n" if context else ""
    return (
        f"Ich brauche Hilfe bei der Fehlersuche.\n\nFEHLER:\n{error}\n{ctx}"
        f"\nAUFGABE:\n- Ursache erklären\n- 3-5 Checks\n- Konkrete Fix-Schritte."
    )

@mcp.tool()
async def process_data(data_uri: str, ctx: Context) -> dict:
    await ctx.info(f"Processing {data_uri} …")
    res = await ctx.read_resource(data_uri)
    await ctx.report_progress(50, 100)
    return {"length": len(res)}


if __name__ == "__main__":
    mcp.run()  # STDIO ist Default-Transport
