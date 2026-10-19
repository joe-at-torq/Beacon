import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("TIM_DATA_DIR", tempfile.mkdtemp(prefix="tim-test-"))
os.environ["TIM_DISABLE_SCHEDULER"] = "1"
os.environ["TIM_SECURE_COOKIES"] = "0"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402

from app.bootstrap import init_app_state  # noqa: E402
from app.config import config  # noqa: E402
from app.db import SessionLocal  # noqa: E402
from app.security import reset_secrets_cache  # noqa: E402


@pytest.fixture(autouse=True)
def fresh_state(tmp_path):
    config.data_dir = tmp_path
    reset_secrets_cache()
    init_app_state(f"sqlite:///{tmp_path / 'test.db'}")
    yield


@pytest.fixture
def db():
    session = SessionLocal()
    yield session
    session.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture
def admin_client(client):
    r = client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    assert r.status_code == 200
    r = client.post("/api/auth/change-password", json={"current_password": "admin", "new_password": "Sup3rSecret!"})
    assert r.status_code == 200
    return client
