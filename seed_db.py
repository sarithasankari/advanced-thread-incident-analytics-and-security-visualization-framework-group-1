"""
Seeding script to initialize databases and insert Admin, Analyst, and Viewer accounts.
"""

import os
import sys

# Path configuration
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from src.database_manager import initialize_database, get_db, db_create_user, db_get_user_by_username
from api.auth import hash_password

def seed():
    print("Initializing database...")
    initialize_database()
    
    print("Seeding default security roles...")
    with get_db() as db:
        # Check Admin
        admin = db_get_user_by_username(db, "admin")
        if not admin:
            db_create_user(db, "admin", hash_password("admin123"), "Admin")
            print("  Created default user: admin / admin123 (Role: Admin)")
        else:
            print("  User 'admin' already exists.")
            
        # Check Analyst
        analyst = db_get_user_by_username(db, "analyst")
        if not analyst:
            db_create_user(db, "analyst", hash_password("analyst123"), "Security Analyst")
            print("  Created default user: analyst / analyst123 (Role: Security Analyst)")
        else:
            print("  User 'analyst' already exists.")
            
        # Check Viewer
        viewer = db_get_user_by_username(db, "viewer")
        if not viewer:
            db_create_user(db, "viewer", hash_password("viewer123"), "Viewer")
            print("  Created default user: viewer / viewer123 (Role: Viewer)")
        else:
            print("  User 'viewer' already exists.")
            
    print("Database seeding completed successfully!")

if __name__ == "__main__":
    seed()
