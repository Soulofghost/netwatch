import ipaddress
import socket
import time
from typing import List, Dict, Any, Optional

WELL_KNOWN_SERVICES = {
    21: {"service": "FTP", "risk": "MEDIUM"},
    22: {"service": "SSH", "risk": "LOW"},
    23: {"service": "Telnet", "risk": "CRITICAL"},
    25: {"service": "SMTP", "risk": "LOW"},
    53: {"service": "DNS", "risk": "LOW"},
    80: {"service": "HTTP", "risk": "LOW"},
    110: {"service": "POP3", "risk": "MEDIUM"},
    143: {"service": "IMAP", "risk": "MEDIUM"},
    443: {"service": "HTTPS", "risk": "LOW"},
    445: {"service": "SMB", "risk": "HIGH"},
    3306: {"service": "MySQL", "risk": "MEDIUM"},
    3389: {"service": "RDP", "risk": "HIGH"},
    5432: {"service": "PostgreSQL", "risk": "LOW"},
    6379: {"service": "Redis", "risk": "HIGH"},
    8080: {"service": "HTTP-Proxy", "risk": "LOW"},
    8443: {"service": "HTTPS-Alt", "risk": "LOW"},
    27017: {"service": "MongoDB", "risk": "HIGH"},
}

class NetworkScanner:
    @staticmethod
    def parse_cidr(cidr: str) -> Dict[str, Any]:
        """
        Parses and validates an IPv4/IPv6 CIDR range.
        """
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            hosts = list(net.hosts())
            return {
                "valid": True,
                "cidr": str(net),
                "network_address": str(net.network_address),
                "broadcast_address": str(net.broadcast_address),
                "netmask": str(net.netmask),
                "num_addresses": net.num_addresses,
                "total_usable_hosts": len(hosts),
                "sample_hosts": [str(h) for h in hosts[:10]]
            }
        except ValueError as e:
            return {
                "valid": False,
                "error": str(e)
            }

    @staticmethod
    def probe_port(ip: str, port: int, timeout_s: float = 0.5) -> Dict[str, Any]:
        """
        Performs a non-blocking TCP socket connect probe.
        """
        start = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout_s)

        service_meta = WELL_KNOWN_SERVICES.get(port, {"service": "UNKNOWN", "risk": "LOW"})
        state = "CLOSED"
        banner = ""

        try:
            res = sock.connect_ex((ip, port))
            if res == 0:
                state = "OPEN"
                # Quick banner grab attempt
                try:
                    sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    data = sock.recv(256)
                    if data:
                        banner = data.decode('utf-8', errors='ignore').split('\r\n')[0]
                except Exception:
                    banner = ""
            elif res in [11, 10035, 10060]: # WSAETIMEDOUT / EAGAIN
                state = "FILTERED"
        except Exception:
            state = "FILTERED"
        finally:
            sock.close()

        latency_ms = round((time.perf_counter() - start) * 1000, 2)

        return {
            "port": port,
            "protocol": "TCP",
            "state": state,
            "service": service_meta["service"],
            "risk_level": service_meta["risk"] if state == "OPEN" else "NONE",
            "banner": banner,
            "latency_ms": latency_ms
        }

    @staticmethod
    def scan_host(ip: str, ports: List[int], timeout_s: float = 0.3) -> Dict[str, Any]:
        """
        Scans a targeted host for open ports.
        """
        findings = []
        for port in ports:
            findings.append(NetworkScanner.probe_port(ip, port, timeout_s))

        open_findings = [f for f in findings if f["state"] == "OPEN"]
        highest_risk = "LOW"
        if any(f["risk_level"] == "CRITICAL" for f in open_findings):
            highest_risk = "CRITICAL"
        elif any(f["risk_level"] == "HIGH" for f in open_findings):
            highest_risk = "HIGH"
        elif any(f["risk_level"] == "MEDIUM" for f in open_findings):
            highest_risk = "MEDIUM"

        return {
            "ip": ip,
            "is_alive": len(open_findings) > 0,
            "total_ports_probed": len(ports),
            "open_ports_count": len(open_findings),
            "highest_risk": highest_risk,
            "findings": findings
        }
