import os

PORT = int(os.getenv("NETWATCH_PORT", "8000"))
DB_PATH = os.getenv("NETWATCH_DB_PATH", "backend/data/netwatch.db")
