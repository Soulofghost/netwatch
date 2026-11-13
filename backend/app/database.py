import os
import sqlite3
from backend.app.config import DB_PATH

def get_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS subnets (
        id TEXT PRIMARY KEY,
        cidr TEXT UNIQUE,
        label TEXT,
        network_address TEXT,
        broadcast_address TEXT,
        netmask TEXT,
        total_hosts INTEGER,
        created_at TEXT
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS network_assets (
        id TEXT PRIMARY KEY,
        subnet_id TEXT,
        ip_address TEXT UNIQUE,
        hostname TEXT,
        mac_address TEXT,
        os_family TEXT,
        status TEXT,
        is_rogue INTEGER DEFAULT 0,
        open_ports_count INTEGER DEFAULT 0,
        last_seen TEXT
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS port_findings (
        id TEXT PRIMARY KEY,
        asset_id TEXT,
        port INTEGER,
        protocol TEXT,
        service TEXT,
        state TEXT,
        banner TEXT,
        risk_level TEXT,
        scanned_at TEXT
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scan_jobs (
        id TEXT PRIMARY KEY,
        target TEXT,
        scan_type TEXT,
        hosts_found INTEGER,
        ports_scanned INTEGER,
        duration_ms REAL,
        status TEXT,
        executed_at TEXT
    );
    """)

    conn.commit()
    conn.close()

init_db()
