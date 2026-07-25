# Purpose: Provide a reusable database connection so every module doesn't have to duplicate sqlite3.connect(...)
# Responsibility: Give other modules access to the database.

import sqlite3
from pathlib import Path

# Define project paths
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATABASE_PATH = PROJECT_ROOT / "signaliq.db"


def get_database_connection():
    
    """
    Create and return a connection to the SignalIQ SQLite database.
    """
    connection = sqlite3.connect(DATABASE_PATH)
        
    # return the connection object
    return connection