from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class RegisterSubnetRequest(BaseModel):
    cidr: str = Field(..., description="IPv4 CIDR block, e.g. 192.168.1.0/24")
    label: str = Field(..., description="Human-readable subnet label, e.g. Office LAN")

class SubnetResponse(BaseModel):
    id: str
    cidr: str
    label: str
    network_address: str
    broadcast_address: str
    netmask: str
    total_hosts: int
    created_at: str

class ScanHostRequest(BaseModel):
    ip: str = Field(..., description="Target IPv4 address, e.g. 127.0.0.1 or 192.168.1.1")
    ports: Optional[List[int]] = Field(default=[21, 22, 23, 80, 443, 3306, 5432, 6379, 8080])

class PortFindingItem(BaseModel):
    port: int
    protocol: str
    state: str
    service: str
    risk_level: str
    banner: str
    latency_ms: float

class ScanHostResponse(BaseModel):
    ip: str
    is_alive: bool
    total_ports_probed: int
    open_ports_count: int
    highest_risk: str
    findings: List[PortFindingItem]

class AssetResponse(BaseModel):
    id: str
    subnet_id: Optional[str]
    ip_address: str
    hostname: str
    mac_address: str
    os_family: str
    status: str
    is_rogue: bool
    open_ports_count: int
    last_seen: str

class ScanJobResponse(BaseModel):
    id: str
    target: str
    scan_type: str
    hosts_found: int
    ports_scanned: int
    duration_ms: float
    status: str
    executed_at: str
