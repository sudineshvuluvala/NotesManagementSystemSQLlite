"""SQLite database helpers shared by the Flask application and init_db.py."""
import os
import sqlite3
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent

# Parse SQLite TIMESTAMP columns as datetime objects for the existing Jinja templates.
sqlite3.register_converter("TIMESTAMP", lambda raw: datetime.fromisoformat(raw.decode("utf-8")))
load_dotenv(BASE_DIR / ".env")


def database_path() -> Path:
    """Return the configured SQLite database file path."""
    configured = os.getenv("DATABASE_PATH", "notes.db").strip() or "notes.db"
    path = Path(configured).expanduser()
    return path if path.is_absolute() else BASE_DIR / path


def get_db_connection() -> sqlite3.Connection:
    """Open a SQLite connection with row access by column name and foreign keys."""
    conn = sqlite3.connect(
        str(database_path()),
        timeout=10,
        detect_types=sqlite3.PARSE_DECLTYPES,
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 10000")
    return conn


def init_database() -> Path:
    """Create the schema if it does not exist. Existing data is preserved."""
    schema_path = BASE_DIR / "schema.sql"
    conn = get_db_connection()
    try:
        conn.executescript(schema_path.read_text(encoding="utf-8"))
        conn.commit()
    finally:
        conn.close()
    return database_path()
