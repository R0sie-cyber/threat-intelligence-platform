import sqlite3
from pathlib import Path

# Define project paths
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATABASE_PATH = PROJECT_ROOT / "signaliq.db"
SCHEMA_PATH = Path(__file__).parent / "schema.sql"

def initialize_database():
    # Connect to (or create) the SQLite database
    connection = sqlite3.connect(DATABASE_PATH)
        
    # Create a cursor
    cursor = connection.cursor()
    
    # Read the SQL schema
    with open(SCHEMA_PATH, "r", encoding="utf-8") as schema_file:
        schema = schema_file.read()


    # Execute the schema
    cursor.executescript(schema)

    # Save changes
    connection.commit()

    # Close resources
    cursor.close()
    connection.close()

    # Print success message
    print("SignalIQ database initialized successfully.")

if __name__ == "__main__":
    initialize_database()


