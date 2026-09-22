from pathlib import Path

import pytest

from otaudit.scope import load_scope
from otaudit.synthesis import build_sample_capture

SAMPLE_SCOPE = Path(__file__).resolve().parent.parent / "samples" / "scope.yaml"


@pytest.fixture(scope="session")
def sample_capture(tmp_path_factory):
    return build_sample_capture(tmp_path_factory.mktemp("capture") / "demo.pcap")


@pytest.fixture
def sample_scope():
    return load_scope(SAMPLE_SCOPE)
