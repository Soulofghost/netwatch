import uuid
import hashlib
from typing import Dict, Any, List

class InventoryEngine:
    @staticmethod
    def generate_simulated_mac(ip: str) -> str:
        """
        Deterministically derives a simulated MAC address from IP address.
        """
        digest = hashlib.md5(ip.encode()).hexdigest()
        mac = ":".join([digest[i:i+2] for i in range(0, 12, 2)]).upper()
        return mac

    @staticmethod
    def detect_rogue_status(hostname: str, ip: str, open_ports: int) -> bool:
        """
        Flags devices as rogue if hostname indicates unauthorized device or exposes dangerous ports.
        """
        suspicious_keywords = ["unknown", "unregistered", "guest", "kali", "hack", "esp8266"]
        h_lower = hostname.lower()
        if any(k in h_lower for k in suspicious_keywords):
            return True
        if ip.endswith(".250") or ip.endswith(".254") and "gateway" not in h_lower:
            return True
        return False
