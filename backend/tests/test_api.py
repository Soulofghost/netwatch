import pytest
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)

def test_healthcheck():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["service"] == "NetWatch"

def test_stats_endpoint():
    res = client.get("/api/stats")
    assert res.status_code == 200
    data = res.json()
    assert "totalSubnets" in data
    assert "totalAssets" in data

def test_register_subnet_and_list():
    payload = {
        "cidr": "10.0.50.0/24",
        "label": "Production VPC DMZ"
    }
    res = client.post("/api/subnets", json=payload)
    assert res.status_code == 201
    data = res.json()
    assert data["cidr"] == "10.0.50.0/24"
    assert data["total_hosts"] == 254

    list_res = client.get("/api/subnets")
    assert list_res.status_code == 200
    subnets = list_res.json()
    assert any(s["cidr"] == "10.0.50.0/24" for s in subnets)

def test_assets_listing():
    res = client.get("/api/assets")
    assert res.status_code == 200
    assets = res.json()
    assert isinstance(assets, list)

def test_scan_host_endpoint():
    payload = {
        "ip": "127.0.0.1",
        "ports": [80, 443]
    }
    res = client.post("/api/scan/host", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["ip"] == "127.0.0.1"
    assert len(data["findings"]) == 2

def test_scan_jobs():
    res = client.get("/api/scan/jobs")
    assert res.status_code == 200
    jobs = res.json()
    assert isinstance(jobs, list)
