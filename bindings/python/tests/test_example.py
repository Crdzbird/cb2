from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "token_service.py"


@pytest.mark.skipif(not EXAMPLE.is_file(), reason="examples/token_service.py is not next to the tests")
def test_token_service_demo() -> None:
    result = subprocess.run([sys.executable, str(EXAMPLE)], capture_output=True, text=True, timeout=120, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "all steps behaved as expected" in result.stdout
    assert "FAIL" not in result.stdout
