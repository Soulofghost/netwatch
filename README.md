# NetWatch - Network Inventory Discovery & Port Scanner

NetWatch is an autonomous network asset discovery and host port diagnostic platform. Built with Python 3.11, FastAPI, and SQLite WAL, NetWatch provides network engineers and security analysts with real-time IPv4 CIDR subnet calculation, non-blocking TCP socket diagnostics, service fingerprinting, and unauthorized rogue device detection.

## Core Capabilities
- **CIDR Subnet IP Topology:** Parses and validates arbitrary IPv4 CIDR blocks (e.g. `/24`, `/28`), deriving network IDs, broadcast addresses, subnet masks, and total usable host allocations.
- **Concurrent TCP Port Scanner:** Multi-threaded, non-blocking socket probes across well-known services (FTP, SSH, Telnet, DNS, HTTP, HTTPS, MySQL, Postgres, Redis, RDP, MongoDB).
- **Service & Banner Fingerprinting:** Collects service headers and measures RTT connection latency in milliseconds.
- **Rogue Device Detection:** Evaluates hostname signatures and exposed attack surfaces to flag unauthorized or unmanaged nodes.
- **Persistent Asset Inventory:** Stores discovery history and port state drift in SQLite using Write-Ahead Logging (WAL).

## Technology Stack
- **Backend:** Python 3.11+, FastAPI, Pydantic v2, Pytest
- **Database:** SQLite (WAL mode)
- **Frontend:** Vanilla JavaScript, Modern CSS Grid/Flexbox, Dark SecOps UI
- **DevOps:** Docker, Docker Compose, GitHub Actions CI

## Quickstart

```bash
# Clone the repository
git clone https://github.com/Soulofghost/netwatch.git
cd netwatch

# Install dependencies
pip install -r backend/requirements.txt

# Run test suite
pytest -v

# Run the API server
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
```

## API Endpoints
- `GET /api/health` - Healthcheck and scanner engine status.
- `GET /api/stats` - Network-wide summary metrics (subnets, assets, rogues, open ports).
- `GET /api/subnets` - List all registered CIDR subnets.
- `POST /api/subnets` - Register a new CIDR range and discover initial host topology.
- `GET /api/assets` - List all discovered network host assets and rogue status.
- `POST /api/scan/host` - Execute TCP socket probes against a target host IP.
- `GET /api/scan/jobs` - Retrieve historical scan job telemetry.

## Author
Alvin MS ([@Soulofghost](https://github.com/Soulofghost))
