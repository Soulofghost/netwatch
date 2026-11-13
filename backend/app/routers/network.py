import uuid
import datetime
import time
from fastapi import APIRouter, HTTPException, status
from typing import List, Dict, Any

from backend.app.database import get_connection
from backend.app.schemas import (
    RegisterSubnetRequest, SubnetResponse,
    ScanHostRequest, ScanHostResponse,
    AssetResponse, ScanJobResponse
)
from backend.app.engine.scanner import NetworkScanner
from backend.app.engine.inventory import InventoryEngine

router = APIRouter(prefix="/api", tags=["network"])

@router.get("/health")
def healthcheck():
    return {
        "status": "ok",
        "service": "NetWatch",
        "version": "1.0.0",
        "engine": "CIDR IPv4 Subnet Scanner & Network Asset Discovery"
    }

@router.get("/stats")
def get_stats():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as c FROM subnets;")
    total_subnets = cursor.fetchone()["c"]

    cursor.execute("SELECT COUNT(*) as c FROM network_assets;")
    total_assets = cursor.fetchone()["c"]

    cursor.execute("SELECT COUNT(*) as c FROM network_assets WHERE is_rogue = 1;")
    rogue_assets = cursor.fetchone()["c"]

    cursor.execute("SELECT COUNT(*) as c FROM port_findings WHERE state = 'OPEN';")
    open_ports_count = cursor.fetchone()["c"]

    cursor.execute("SELECT COUNT(*) as c FROM port_findings WHERE state = 'OPEN' AND risk_level IN ('HIGH', 'CRITICAL');")
    high_risk_ports = cursor.fetchone()["c"]

    conn.close()

    return {
        "totalSubnets": total_subnets,
        "totalAssets": total_assets,
        "rogueAssets": rogue_assets,
        "openPortsCount": open_ports_count,
        "highRiskPorts": high_risk_ports
    }

@router.get("/subnets", response_model=List[SubnetResponse])
def list_subnets():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM subnets ORDER BY created_at DESC;")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

@router.post("/subnets", response_model=SubnetResponse, status_code=status.HTTP_201_CREATED)
def register_subnet(payload: RegisterSubnetRequest):
    parsed = NetworkScanner.parse_cidr(payload.cidr)
    if not parsed["valid"]:
        raise HTTPException(status_code=400, detail=f"Invalid CIDR: {parsed.get('error')}")

    conn = get_connection()
    cursor = conn.cursor()

    subnet_id = "sub-" + str(uuid.uuid4())[:8]
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    try:
        cursor.execute("""
        INSERT INTO subnets (id, cidr, label, network_address, broadcast_address, netmask, total_hosts, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            subnet_id,
            parsed["cidr"],
            payload.label,
            parsed["network_address"],
            parsed["broadcast_address"],
            parsed["netmask"],
            parsed["total_usable_hosts"],
            now_iso
        ))

        # Seed discovery with sample baseline nodes
        sample_nodes = [
            ("Gateway Router", parsed["network_address"].rsplit('.', 1)[0] + ".1", "Cisco IOS", False, [22, 80, 443]),
            ("Corporate DNS Server", parsed["network_address"].rsplit('.', 1)[0] + ".2", "Ubuntu Linux", False, [22, 53]),
            ("Database Primary", parsed["network_address"].rsplit('.', 1)[0] + ".10", "Debian Linux", False, [22, 5432]),
            ("Unregistered Device", parsed["network_address"].rsplit('.', 1)[0] + ".250", "Unknown OS", True, [23, 8080]),
        ]

        for name, ip, os_fam, is_rogue, open_p in sample_nodes:
            asset_id = "ast-" + str(uuid.uuid4())[:8]
            mac = InventoryEngine.generate_simulated_mac(ip)
            cursor.execute("""
            INSERT OR IGNORE INTO network_assets (id, subnet_id, ip_address, hostname, mac_address, os_family, status, is_rogue, open_ports_count, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, 'ONLINE', ?, ?, ?);
            """, (asset_id, subnet_id, ip, name, mac, os_fam, 1 if is_rogue else 0, len(open_p), now_iso))

            for p in open_p:
                finding_id = "fnd-" + str(uuid.uuid4())[:8]
                risk = "CRITICAL" if p == 23 else "HIGH" if p in [3389, 6379] else "LOW"
                cursor.execute("""
                INSERT INTO port_findings (id, asset_id, port, protocol, service, state, banner, risk_level, scanned_at)
                VALUES (?, ?, ?, 'TCP', 'TCP-Service', 'OPEN', 'Ready', ?, ?);
                """, (finding_id, asset_id, p, risk, now_iso))

        conn.commit()
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=400, detail=f"Failed to register subnet: {str(e)}")

    conn.close()

    return {
        "id": subnet_id,
        "cidr": parsed["cidr"],
        "label": payload.label,
        "network_address": parsed["network_address"],
        "broadcast_address": parsed["broadcast_address"],
        "netmask": parsed["netmask"],
        "total_hosts": parsed["total_usable_hosts"],
        "created_at": now_iso
    }

@router.get("/assets", response_model=List[AssetResponse])
def list_assets():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM network_assets ORDER BY ip_address ASC;")
    rows = cursor.fetchall()
    conn.close()
    return [
        {
            **dict(r),
            "is_rogue": bool(r["is_rogue"])
        } for r in rows
    ]

@router.post("/scan/host", response_model=ScanHostResponse)
def scan_host(payload: ScanHostRequest):
    ports = payload.ports or [21, 22, 23, 80, 443, 3306, 5432, 6379, 8080]
    result = NetworkScanner.scan_host(payload.ip, ports)

    # Record scan job
    conn = get_connection()
    cursor = conn.cursor()
    job_id = "job-" + str(uuid.uuid4())[:8]
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    cursor.execute("""
    INSERT INTO scan_jobs (id, target, scan_type, hosts_found, ports_scanned, duration_ms, status, executed_at)
    VALUES (?, ?, 'HOST_PORT_SCAN', ?, ?, ?, 'COMPLETED', ?);
    """, (job_id, payload.ip, 1 if result["is_alive"] else 0, len(ports), 150.0, now_iso))

    conn.commit()
    conn.close()

    return result

@router.get("/scan/jobs", response_model=List[ScanJobResponse])
def list_scan_jobs(limit: int = 20):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scan_jobs ORDER BY executed_at DESC LIMIT ?;", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]
