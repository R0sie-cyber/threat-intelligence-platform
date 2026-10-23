
# Purpose: Provide a reusable SQLite database connection.
# Responsibility: Ensure all modules use the same database configuration.

import sqlite3
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATABASE_PATH = PROJECT_ROOT / "signaliq.db"


def get_database_connection():
    """
    Create and return a connection to the SignalIQ database.

    Foreign-key enforcement is enabled for each connection.
    """
    connection = sqlite3.connect(DATABASE_PATH)
    connection.execute("PRAGMA foreign_keys = ON")

    return connection
