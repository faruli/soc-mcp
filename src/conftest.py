# conftest.py
import sys
from pathlib import Path
import warnings
from dotenv import load_dotenv
import pytest

def _try_load_env():
    # 1) Bevorzugt: src/.env
    env1 = Path(__file__).parent.parent / "src" / ".env"
    # 2) Fallback: Projektroot/.env (falls du später mal umziehst)
    env2 = Path(__file__).parent.parent / ".env"

    for p in (env1, env2):
        if p.exists():
            load_dotenv(p)
            return
    warnings.warn("Keine .env gefunden (erwartet z. B. src/.env). Tests laufen weiter (externe Tests werden ggf. geskippt).")

def pytest_configure(config):
    _try_load_env()

# optional: VT-Key für Tests vorhanden 
@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")

# audit.jsonl pro Lauf leeren, damit das Dashboard frische Daten sieht
@pytest.fixture(autouse=True, scope="session")
def _clean_audit():
    p = Path("src/logs/audit.jsonl")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("", encoding="utf-8")
    yield


ROOT = Path(__file__).resolve().parents[1]   # Projektroot
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))            # damit "import src.***" funktioniert
