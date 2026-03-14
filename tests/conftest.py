from pathlib import Path
import sys

import pytest

# Ensure repo root is importable so "app" can be resolved
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.parsers.parser_dispatcher import ParserDispatcher


@pytest.fixture
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture
def standalone_config(repo_root):
    dispatcher = ParserDispatcher()
    _, config = dispatcher.parse(str(repo_root / "sample_stand_alone.xml"))
    return config


@pytest.fixture
def panorama_config(repo_root):
    dispatcher = ParserDispatcher()
    _, config = dispatcher.parse(str(repo_root / "sample_panorama.xml"))
    return config