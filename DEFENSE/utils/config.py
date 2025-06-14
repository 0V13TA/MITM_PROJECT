import os

# 1. honour env-variable, fallback to project root
DB_PATH = os.getenv("MITM_DB_PATH") or os.path.join(
    os.path.dirname(__file__), "..", "..", "mitm.db"
)
