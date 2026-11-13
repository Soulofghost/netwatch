import pytest
from backend.app.engine.scanner import NetworkScanner
from backend.app.engine.inventory import InventoryEngine

def test_cidr_parsing_valid():
    res = NetworkScanner.parse_cidr("192.168.1.0/24")
    assert res["valid"] is True
    assert res["network_address"] == "192.168.1.0"
    assert res["broadcast_address"] == "192.168.1.255"
    assert res["netmask"] == "255.255.255.0"
    assert res["total_usable_hosts"] == 254

def test_cidr_parsing_invalid():
    res = NetworkScanner.parse_cidr("999.999.999.999/33")
    assert res["valid"] is False
    assert "error" in res

def test_port_probe_structure():
    # Probe a loopback port (closed or filtered usually)
    probe = NetworkScanner.probe_port("127.0.0.1", 65432, timeout_s=0.1)
    assert probe["port"] == 65432
    assert probe["protocol"] == "TCP"
    assert probe["state"] in ["CLOSED", "FILTERED", "OPEN"]
    assert "latency_ms" in probe

def test_host_scan_structure():
    scan = NetworkScanner.scan_host("127.0.0.1", [80, 443], timeout_s=0.1)
    assert scan["ip"] == "127.0.0.1"
    assert scan["total_ports_probed"] == 2
    assert len(scan["findings"]) == 2

def test_rogue_detection():
    # Rogue keywords
    assert InventoryEngine.detect_rogue_status("kali-attacker", "192.168.1.55", 3) is True
    assert InventoryEngine.detect_rogue_status("corp-printer", "192.168.1.250", 1) is True
    # Normal authorized node
    assert InventoryEngine.detect_rogue_status("corp-gateway-01", "192.168.1.1", 2) is False
