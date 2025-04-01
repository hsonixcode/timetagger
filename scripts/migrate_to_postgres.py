#!/usr/bin/env python
"""
Migrate TimeTagger data from SQLite to PostgreSQL.

This script:
1. Initializes the PostgreSQL database
2. Migrates all users' data from SQLite to PostgreSQL 
3. Migrates the login database from SQLite to PostgreSQL
4. Validates the migration
"""

import os
import sys
import logging
import time
import json
from pathlib import Path
import argparse
from datetime import datetime

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("migration.log")
    ]
)
logger = logging.getLogger("timetagger.migration")

# Add parent directory to path to import timetagger modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from timetagger.server.db_utils import init_database, migrate_user_from_sqlite, migrate_all_users_from_sqlite
from timetagger.server._utils import ROOT_USER_DIR

def validate_migration():
    """Validate that the migration was successful by comparing record counts."""
    from timetagger.server.db_utils import get_session
    from timetagger.server.db_utils import Record, Settings, UserInfo
    from sqlalchemy import func
    import sqlite3
    
    session = get_session()
    
    # Get count of records in PostgreSQL
    pg_record_count = session.query(func.count(Record.key)).scalar()
    pg_settings_count = session.query(func.count(Settings.key)).scalar()
    pg_userinfo_count = session.query(func.count(UserInfo.key)).scalar()
    
    # Get count of records in SQLite databases
    sqlite_record_count = 0
    sqlite_settings_count = 0
    sqlite_userinfo_count = 0
    
    # Count records in all SQLite databases
    sqlite_files = list(Path(ROOT_USER_DIR).glob("*.db"))
    for sqlite_file in sqlite_files:
        if 'login_users.db' in str(sqlite_file):
            continue  # Skip the login database
            
        try:
            conn = sqlite3.connect(str(sqlite_file))
            cursor = conn.cursor()
            
            # Check if tables exist
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='records'")
            if cursor.fetchone():
                cursor.execute("SELECT COUNT(*) FROM records")
                sqlite_record_count += cursor.fetchone()[0]
            
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='settings'")
            if cursor.fetchone():
                cursor.execute("SELECT COUNT(*) FROM settings")
                sqlite_settings_count += cursor.fetchone()[0]
            
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='userinfo'")
            if cursor.fetchone():
                cursor.execute("SELECT COUNT(*) FROM userinfo")
                sqlite_userinfo_count += cursor.fetchone()[0]
                
            conn.close()
        except Exception as e:
            logger.error(f"Error counting records in {sqlite_file}: {e}")
    
    # Compare counts
    logger.info(f"PostgreSQL record count: {pg_record_count}, SQLite record count: {sqlite_record_count}")
    logger.info(f"PostgreSQL settings count: {pg_settings_count}, SQLite settings count: {sqlite_settings_count}")
    logger.info(f"PostgreSQL userinfo count: {pg_userinfo_count}, SQLite userinfo count: {sqlite_userinfo_count}")
    
    # Calculate percentage migrated
    if sqlite_record_count > 0:
        records_pct = (pg_record_count / sqlite_record_count) * 100
        logger.info(f"Records migrated: {records_pct:.1f}%")
    
    if sqlite_settings_count > 0:
        settings_pct = (pg_settings_count / sqlite_settings_count) * 100
        logger.info(f"Settings migrated: {settings_pct:.1f}%")
        
    if sqlite_userinfo_count > 0:
        userinfo_pct = (pg_userinfo_count / sqlite_userinfo_count) * 100
        logger.info(f"UserInfo migrated: {userinfo_pct:.1f}%")
    
    session.close()
    
    return {
        "pg_records": pg_record_count,
        "sqlite_records": sqlite_record_count,
        "pg_settings": pg_settings_count,
        "sqlite_settings": sqlite_settings_count,
        "pg_userinfo": pg_userinfo_count,
        "sqlite_userinfo": sqlite_userinfo_count,
    }

def migrate_login_database():
    """Migrate the login database from SQLite to PostgreSQL."""
    from timetagger.multiuser.login_tracker import LoginTracker
    import sqlite3
    
    logger.info("Migrating login database...")
    
    # Path to the SQLite login database
    login_db_path = os.path.join(ROOT_USER_DIR, "login_users.db")
    
    if not os.path.exists(login_db_path):
        logger.warning(f"SQLite login database not found at {login_db_path}")
        return False
        
    try:
        # Connect to the SQLite database
        conn = sqlite3.connect(login_db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Check if the table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='login_users'")
        if not cursor.fetchone():
            logger.warning("No login_users table found in the SQLite database")
            return False
            
        # Get all users from the SQLite database
        cursor.execute("SELECT * FROM login_users")
        rows = cursor.fetchall()
        
        if not rows:
            logger.warning("No users found in the SQLite login database")
            return False
            
        # Create a new login tracker for PostgreSQL
        login_tracker = LoginTracker()
        
        # Migrate each user
        success_count = 0
        for row in rows:
            user_dict = dict(row)
            
            # Parse JSON metadata
            try:
                if user_dict.get("metadata"):
                    metadata = json.loads(user_dict["metadata"])
                else:
                    metadata = {}
            except (json.JSONDecodeError, TypeError) as e:
                logger.warning(f"Error parsing metadata for user {user_dict.get('email')}: {e}")
                metadata = {}
                
            # Convert to datetime object if it's a timestamp
            last_login = user_dict.get("last_login")
            if isinstance(last_login, (int, float)):
                last_login = datetime.fromtimestamp(last_login)
                
            # Create user data for PostgreSQL
            user_data = {
                "email": user_dict.get("email"),
                "username": user_dict.get("username"),
                "role": user_dict.get("role", "user"),
                "user_type": user_dict.get("user_type", "local"),
                "is_allowed": user_dict.get("access") != "not allowed",
                "source_db": user_dict.get("source_db", ""),
                "metadata": metadata,
                "last_login": last_login
            }
            
            # Record the login
            success = login_tracker.record_login(user_data)
            if success:
                success_count += 1
                
        logger.info(f"Migrated {success_count}/{len(rows)} users from the login database")
        conn.close()
        
        return success_count > 0
        
    except Exception as e:
        logger.error(f"Error migrating login database: {e}")
        return False

def main():
    """Main migration function."""
    parser = argparse.ArgumentParser(description="Migrate TimeTagger data from SQLite to PostgreSQL")
    parser.add_argument("--username", help="Migrate a specific user (by username)")
    parser.add_argument("--all", action="store_true", help="Migrate all users")
    parser.add_argument("--validate", action="store_true", help="Validate the migration")
    parser.add_argument("--login-db", action="store_true", help="Migrate the login database")
    
    args = parser.parse_args()
    
    start_time = time.time()
    logger.info("Starting migration from SQLite to PostgreSQL...")
    
    # Initialize the PostgreSQL database
    try:
        init_database()
        logger.info("PostgreSQL database initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize PostgreSQL database: {e}")
        return 1
    
    # Migrate a specific user
    if args.username:
        logger.info(f"Migrating user {args.username}...")
        try:
            success = migrate_user_from_sqlite(args.username)
            if success:
                logger.info(f"Successfully migrated user {args.username}")
            else:
                logger.error(f"Failed to migrate user {args.username}")
                return 1
        except Exception as e:
            logger.error(f"Error migrating user {args.username}: {e}")
            return 1
            
    # Migrate all users
    if args.all:
        logger.info("Migrating all users...")
        try:
            results = migrate_all_users_from_sqlite()
            success_count = sum(1 for success in results.values() if success)
            logger.info(f"Migrated {success_count}/{len(results)} users successfully")
            
            if success_count < len(results):
                failed_users = [username for username, success in results.items() if not success]
                logger.warning(f"Failed to migrate these users: {', '.join(failed_users)}")
        except Exception as e:
            logger.error(f"Error migrating all users: {e}")
            return 1
    
    # Migrate the login database
    if args.login_db:
        try:
            success = migrate_login_database()
            if success:
                logger.info("Successfully migrated the login database")
            else:
                logger.warning("Login database migration completed with warnings")
        except Exception as e:
            logger.error(f"Error migrating login database: {e}")
            return 1
            
    # Validate the migration
    if args.validate:
        try:
            logger.info("Validating migration...")
            stats = validate_migration()
            
            # Calculate overall migration percentage
            total_sqlite = stats["sqlite_records"] + stats["sqlite_settings"] + stats["sqlite_userinfo"]
            total_pg = stats["pg_records"] + stats["pg_settings"] + stats["pg_userinfo"]
            
            if total_sqlite > 0:
                overall_pct = (total_pg / total_sqlite) * 100
                logger.info(f"Overall migration completeness: {overall_pct:.1f}%")
                
                if overall_pct < 90:
                    logger.warning("Migration may be incomplete (less than 90% of data migrated)")
            else:
                logger.warning("No SQLite data found to migrate")
        except Exception as e:
            logger.error(f"Error validating migration: {e}")
            return 1
    
    elapsed_time = time.time() - start_time
    logger.info(f"Migration completed in {elapsed_time:.2f} seconds")
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 