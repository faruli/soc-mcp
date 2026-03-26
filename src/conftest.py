# tests/conftest.py
import os
import warnings
from pathlib import Path
from dotenv import load_dotenv, find_dotenv

def _load_env():
    root = Path(__file__).resolve().parent.parent  # Projektwurzel
    candidates = [
        root / "src" / ".env",
        root / ".env",
        Path(find_dotenv(usecwd=True)) if find_dotenv(usecwd=True) else None,
    ]
    for p in candidates:
        if p and p.exists():
            load_dotenv(p, override=False)
            print(f"[pytest] .env geladen: {p}")
            return True
    warnings.warn(
        "Keine .env gefunden – Tests laufen ohne Secrets. "
        "Externe Aufrufe sollten gemockt werden."
    )
    return False

def pytest_sessionstart(session):
    _load_env()
    os.environ.setdefault("PYTHONPATH", str(Path(__file__).resolve().parent.parent))
