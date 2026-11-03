from pathlib import Path
import os
import secrets
from uuid import uuid4

from alembic import command
from alembic.config import Config
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from app.api import create_app
from app.auth import HASHER, Principal
from app.config import StoragePaths
from app.db import Database
from app.models import User
from app.settings import Settings


@pytest.fixture(scope="session")
def credentials():
    password = secrets.token_urlsafe(24)
    return password, HASHER.hash(password)


@pytest.fixture(params=["sqlite"] + (["postgresql"] if os.environ.get("ROOTSENTINEL_TEST_POSTGRES_URL") else []))
def system(tmp_path, credentials, request):
    paths = StoragePaths(tmp_path / "runtime", tmp_path / "artifacts")
    admin_engine = None
    schema = None
    url = f"sqlite:///{paths.database.as_posix()}"
    if request.param == "postgresql":
        base = make_url(os.environ["ROOTSENTINEL_TEST_POSTGRES_URL"])
        admin_engine = create_engine(base, hide_parameters=True)
        schema = "rs_test_" + uuid4().hex
        with admin_engine.begin() as connection:
            connection.execute(text(f'CREATE SCHEMA "{schema}"'))
        url = base.update_query_dict({"options": f"-csearch_path={schema}"}).render_as_string(hide_password=False)
    settings = Settings(paths, url, "local", secure_cookies=False)
    cfg = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
    cfg.attributes["settings"] = settings
    command.upgrade(cfg, "head")
    db = Database(settings.database_url)
    actors = {}
    with db.transaction() as s:
        for username, role in [("admin", "ADMIN"), ("analyst", "ANALYST"), ("employee", "EMPLOYEE"), ("second", "EMPLOYEE")]:
            user = User(username=username, role=role, password_hash=credentials[1])
            s.add(user)
            s.flush()
            actors[username] = Principal(user.id, username, role, "unit-test")
    yield settings, db, actors, cfg
    db.engine.dispose()
    if admin_engine is not None:
        with admin_engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin_engine.dispose()


@pytest.fixture
def client(system):
    app = create_app(system[0])
    with TestClient(app, base_url="http://127.0.0.1:5173", raise_server_exceptions=False) as client:
        client.headers["origin"] = system[0].origin
        yield client


@pytest.fixture
def login(credentials):
    def authenticate(client, name="admin"):
        result = client.post("/api/v1/auth/login", json={"username": name, "password": credentials[0]})
        assert result.status_code == 200, result.text
        client.headers["x-csrf-token"] = result.json()["csrf_token"]
        return result
    return authenticate
