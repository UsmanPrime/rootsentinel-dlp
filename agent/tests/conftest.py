import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from support import MiniGateway, make_dirs  # noqa: E402


@pytest.fixture
def dirs(tmp_path):
    return make_dirs(tmp_path / "agent")


@pytest.fixture
def mini():
    gateway = MiniGateway()
    yield gateway
    gateway.close()


def pytest_collection_modifyitems(config, items):
    for item in items:
        if "posix" in item.keywords and os.name == "nt":
            item.add_marker(pytest.mark.skip(reason="POSIX-only"))
        if "windows" in item.keywords and os.name != "nt":
            item.add_marker(pytest.mark.skip(reason="Windows-only"))
