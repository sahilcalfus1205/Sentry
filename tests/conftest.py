import json
import subprocess
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def fixture_text(name: str) -> str:
    return (FIXTURES / name).read_text()


@pytest.fixture
def fake_subprocess(monkeypatch):
    """Pretend the scanner executable exists and control what subprocess.run returns.

    Usage: fake = fake_subprocess(stdout="...", returncode=0) or fake_subprocess(raises=exc).
    The returned object records the last command in `.calls`.
    """

    class Fake:
        def __init__(self):
            self.calls = []

        def __call__(self, stdout="", stderr="", returncode=0, raises=None, installed=True):
            monkeypatch.setattr(
                "sentry_sec.scanners.base.shutil.which", lambda name: name if installed else None
            )

            def run(command, **kwargs):
                self.calls.append((command, kwargs))
                if raises:
                    raise raises
                return subprocess.CompletedProcess(command, returncode, stdout, stderr)

            monkeypatch.setattr("sentry_sec.scanners.base.subprocess.run", run)
            return self

    return Fake()
