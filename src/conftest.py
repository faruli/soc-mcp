# conftest.py
import sys
from pathlib import Path
import pytest

# optional: VT-Key für Tests vorhanden (falls dein Code ihn beim Import liest)
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
