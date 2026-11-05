import pytest
from app.crypto import fingerprint_bytes, verify_proof
from app.presentation import tree_view
from tests.test_gateway import submit, register, PROTECTED, BENIGN


@pytest.mark.parametrize("count", [0, 1, 2, 3, 5, 16, 17, 129, 10240])
def test_tree_projection_uses_core_and_is_bounded(count):
    fp = fingerprint_bytes(b"A" * (count * 1024))
    view = tree_view(fp, max(0, count - 1))
    assert view.manifest.merkle_root == fp.manifest.merkle_root
    assert len(view.nodes) <= 31 and len(view.chunks) <= 16
    if count:
        assert verify_proof(view.proof.model_dump(), fp.manifest)
        assert view.nodes[-1].digest == fp.manifest.merkle_root
        assert view.nodes[-1].count == count
        assert view.mode == ("full" if count <= 16 else "proof_path")
    else:
        assert view.mode == "empty" and view.proof is None and not view.nodes


def test_uneven_topology_and_offsets():
    fp = fingerprint_bytes(b"A" * 1024 + b"B" * 1024 + b"C")
    view = tree_view(fp, 2, 2, 1)
    nodes = {n.id: n for n in view.nodes}
    assert nodes["0:3"].left == "0:2" and nodes["0:3"].right == "2:1"
    assert nodes["2:1"].selected_path and nodes["0:2"].sibling
    assert view.chunks[0].index == 2 and view.chunks[0].length == 1
    full = tree_view(fingerprint_bytes(b"A" * 8192), 0)
    assert {n.id for n in full.nodes if n.sibling} == {"1:1", "2:2", "4:4"}


def test_overview_empty_and_roles(client, login):
    assert client.get("/api/v1/overview").status_code == 401
    login(client)
    value = client.get("/api/v1/overview").json()
    assert value["total_transfers"] == value["active_assets"] == value["active_incidents"] == 0
    assert len(value["daily"]) == 7 and sum(d["total"] for d in value["daily"]) == 0
    register(client); submit(client, PROTECTED); submit(client, BENIGN)
    value = client.get("/api/v1/overview").json()
    assert value["total_transfers"] == 2 and value["blocked_decisions"] == 1 and value["allowed_decisions"] == 1
    assert value["active_incidents"] == 1 and value["active_assets"] == 1
    assert value["severity"] == {"HIGH": 1} and value["audit_sequence"] > 0
    login(client, "employee")
    value = client.get("/api/v1/overview").json()
    assert value["scope"] == "own" and value["total_transfers"] == 0
    assert all(value[k] is None for k in ["active_incidents", "active_assets", "severity", "audit_sequence"])
    submit(client, BENIGN)
    assert client.get("/api/v1/overview").json()["total_transfers"] == 1


def test_tree_route_trusted_root_proof_and_authorization(client, login):
    login(client)
    response = client.post("/api/v1/assets?label=Uneven", content=b"A" * 1024 + b"B" * 1024 + b"C", headers={"Content-Type": "application/octet-stream"})
    version = response.json()
    route = f'/api/v1/assets/{version["asset_id"]}/versions/{version["id"]}/tree'
    view = client.get(route + "?index=2").json()
    assert view["manifest"]["merkle_root"] == "b77f5d4eb26d8387914ce5dd21753f67c1594343db08d9ffab1ace114aae98de"
    body = {"asset_id": version["asset_id"], "version_id": version["id"], "proof": view["proof"]}
    assert client.post("/api/v1/integrity/verify", json=body).json()["valid"]
    body["proof"]["siblings"][0] = "0" * 64
    assert not client.post("/api/v1/integrity/verify", json=body).json()["valid"]
    assert client.get(route + "?limit=1000").status_code == 422
    assert client.get(route + "?index=3").status_code == 404
    login(client, "employee")
    assert client.get(route).status_code == 403


def test_incident_filter_sort_and_bounds(client, login):
    login(client); register(client)
    first = submit(client, PROTECTED).json()
    second = submit(client, PROTECTED[:1024]).json()
    assert client.get('/api/v1/incidents?severity=HIGH').json()['items'][0]['transfer_id'] == first['id']
    assert client.get('/api/v1/incidents?severity=MEDIUM').json()['items'][0]['transfer_id'] == second['id']
    assert client.get('/api/v1/incidents?order=oldest&limit=1').json()['items'][0]['transfer_id'] == first['id']
    assert client.get('/api/v1/incidents?severity=CRITICAL').status_code == 422
    assert client.get('/api/v1/incidents?order=invalid').status_code == 422
