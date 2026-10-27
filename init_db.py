"""Create the SQLite database and tables for Notes Management System."""
from database import init_database


if __name__ == "__main__":
    path = init_database()
    print("Database and tables created successfully!")
    print(f"SQLite database: {path}")
