"""
Centralized login tracking for TimeTagger.

This module provides functionality for tracking user logins in a central database,
unifying login data for both local and Azure users.
"""

import os
import logging
import sqlite3
import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

from timetagger.server._utils import ROOT_USER_DIR

logger = logging.getLogger("timetagger.multiuser.login_tracker")

# Path to the central login database
LOGIN_DB_PATH = os.path.join(ROOT_USER_DIR, "login_users.db")

class LoginTracker:
    """
    Tracks user logins in a central database.
    """
    
    def __init__(self):
        """
        Initialize the LoginTracker.
        """
        self._db_path = LOGIN_DB_PATH
        self._ensure_db_exists()
    
    def _ensure_db_exists(self):
        """
        Ensure the central login database exists with the required schema.
        """
        try:
            os.makedirs(os.path.dirname(self._db_path), exist_ok=True)
            
            # Create the database and table if they don't exist
            conn = sqlite3.connect(self._db_path)
            cursor = conn.cursor()
            
            # Create the login_users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS login_users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    username TEXT,
                    role TEXT,
                    last_login DATETIME,
                    user_type TEXT CHECK(user_type IN ('local', 'azure')),
                    access TEXT CHECK(access IN ('allowed', 'not allowed')),
                    source_db TEXT,
                    metadata TEXT
                )
            ''')
            
            # Create indices for faster lookups
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_email ON login_users(email)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_username ON login_users(username)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_user_type ON login_users(user_type)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_last_login ON login_users(last_login)')
            
            conn.commit()
            conn.close()
            
            logger.info(f"Login database initialized at {self._db_path}")
        except Exception as e:
            logger.error(f"Error ensuring login database exists: {str(e)}")
    
    async def record_login(self, user_data: Dict[str, Any]) -> bool:
        """
        Record a user login in the central database.
        
        Args:
            user_data: Dictionary containing user information.
                Required keys: email, username, user_type
                Optional keys: role, access, source_db, metadata
                
        Returns:
            bool: True if the login was recorded successfully, False otherwise.
        """
        try:
            # Ensure required fields
            email = user_data.get("email")
            if not email:
                logger.warning("Cannot record login: email is required")
                return False
            
            username = user_data.get("username")
            if not username:
                logger.warning("Cannot record login: username is required")
                return False
            
            user_type = user_data.get("user_type", "local")
            if user_type not in ("local", "azure"):
                user_type = "local"  # Default to local if invalid
            
            # Optional fields with defaults
            role = user_data.get("role", "user")
            access = "allowed" if user_data.get("is_allowed", True) else "not allowed"
            source_db = user_data.get("source_db", "")
            metadata = user_data.get("metadata", {})
            if not isinstance(metadata, dict):
                metadata = {}
            
            # Set last_login to current timestamp
            last_login = int(time.time())
            
            # Connect to the database
            conn = sqlite3.connect(self._db_path)
            cursor = conn.cursor()
            
            # Check if user exists
            cursor.execute("SELECT email FROM login_users WHERE email = ?", (email,))
            user_exists = cursor.fetchone() is not None
            
            if user_exists:
                # Update existing user
                cursor.execute('''
                    UPDATE login_users
                    SET username = ?,
                        role = ?,
                        last_login = ?,
                        user_type = ?,
                        access = ?,
                        source_db = ?,
                        metadata = ?
                    WHERE email = ?
                ''', (
                    username,
                    role,
                    last_login,
                    user_type,
                    access,
                    source_db,
                    json.dumps(metadata),
                    email
                ))
                logger.info(f"Updated login record for user {email}")
            else:
                # Insert new user
                cursor.execute('''
                    INSERT INTO login_users (
                        email,
                        username,
                        role,
                        last_login,
                        user_type,
                        access,
                        source_db,
                        metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    email,
                    username,
                    role,
                    last_login,
                    user_type,
                    access,
                    source_db,
                    json.dumps(metadata)
                ))
                logger.info(f"Created new login record for user {email}")
            
            conn.commit()
            conn.close()
            
            return True
        except Exception as e:
            logger.error(f"Error recording login for user {user_data.get('email')}: {str(e)}")
            return False
    
    def get_all_logins(self, 
                      user_type: Optional[str] = None, 
                      role: Optional[str] = None,
                      access: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get all logins from the central database, with optional filtering.
        
        Args:
            user_type: Optional filter by user type ('local' or 'azure')
            role: Optional filter by role (e.g., 'admin', 'user')
            access: Optional filter by access ('allowed' or 'not allowed')
            
        Returns:
            List of user dictionaries.
        """
        try:
            conn = sqlite3.connect(self._db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Build the query with potential filters
            query = "SELECT * FROM login_users"
            params = []
            
            # Add filters as needed
            filters = []
            if user_type:
                filters.append("user_type = ?")
                params.append(user_type)
            if role:
                filters.append("role = ?")
                params.append(role)
            if access:
                filters.append("access = ?")
                params.append(access)
            
            # Add WHERE clause if filters exist
            if filters:
                query += " WHERE " + " AND ".join(filters)
            
            # Order by last login (most recent first)
            query += " ORDER BY last_login DESC"
            
            # Execute the query
            cursor.execute(query, params)
            
            # Convert rows to dictionaries
            results = []
            for row in cursor.fetchall():
                user_dict = dict(row)
                # Parse JSON metadata
                try:
                    if user_dict.get("metadata"):
                        user_dict["metadata"] = json.loads(user_dict["metadata"])
                    else:
                        user_dict["metadata"] = {}
                except:
                    user_dict["metadata"] = {}
                
                results.append(user_dict)
            
            conn.close()
            return results
        except Exception as e:
            logger.error(f"Error retrieving login data: {str(e)}")
            return []
    
    def get_login_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """
        Get login data for a specific user by email.
        
        Args:
            email: The email of the user to retrieve.
            
        Returns:
            User dictionary or None if not found.
        """
        try:
            conn = sqlite3.connect(self._db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM login_users WHERE email = ?", (email,))
            row = cursor.fetchone()
            
            if row:
                user_dict = dict(row)
                # Parse JSON metadata
                try:
                    if user_dict.get("metadata"):
                        user_dict["metadata"] = json.loads(user_dict["metadata"])
                    else:
                        user_dict["metadata"] = {}
                except:
                    user_dict["metadata"] = {}
                
                conn.close()
                return user_dict
            
            conn.close()
            return None
        except Exception as e:
            logger.error(f"Error retrieving login data for email {email}: {str(e)}")
            return None
    
    def backfill_from_user_databases(self) -> Tuple[int, int]:
        """
        Backfill the login database from existing user databases.
        
        Returns:
            Tuple of (success_count, error_count).
        """
        try:
            from timetagger.multiuser.user import UserManager
            
            user_manager = UserManager()
            all_users = user_manager.get_all_users_classified()
            
            success_count = 0
            error_count = 0
            
            for user in all_users:
                try:
                    # Format user data for the login database
                    email = user.get("email")
                    if not email:
                        logger.warning(f"Skipping user {user.get('username')} during backfill: no email")
                        error_count += 1
                        continue
                    
                    user_data = {
                        "email": email,
                        "username": user.get("username"),
                        "role": user.get("role", "user"),
                        "user_type": "azure" if user.get("source") == "azure" else "local",
                        "is_allowed": user.get("is_allowed", True),
                        "source_db": f"{user.get('username')}.db",
                        "metadata": {
                            "display_name": user.get("display_name"),
                            "auth_type": user.get("auth_type"),
                            "original_last_active": user.get("last_active")
                        }
                    }
                    
                    # Record the login (but don't await since this method isn't async)
                    result = self.record_login_sync(user_data)
                    
                    if result:
                        success_count += 1
                    else:
                        error_count += 1
                
                except Exception as e:
                    logger.error(f"Error backfilling user {user.get('username')}: {str(e)}")
                    error_count += 1
            
            return success_count, error_count
        
        except Exception as e:
            logger.error(f"Error during backfill: {str(e)}")
            return 0, 0
    
    def record_login_sync(self, user_data: Dict[str, Any]) -> bool:
        """
        Synchronous version of record_login for use in backfill.
        """
        try:
            # Ensure required fields
            email = user_data.get("email")
            if not email:
                logger.warning("Cannot record login: email is required")
                return False
            
            username = user_data.get("username")
            if not username:
                logger.warning("Cannot record login: username is required")
                return False
            
            user_type = user_data.get("user_type", "local")
            if user_type not in ("local", "azure"):
                user_type = "local"  # Default to local if invalid
            
            # Optional fields with defaults
            role = user_data.get("role", "user")
            access = "allowed" if user_data.get("is_allowed", True) else "not allowed"
            source_db = user_data.get("source_db", "")
            metadata = user_data.get("metadata", {})
            if not isinstance(metadata, dict):
                metadata = {}
            
            # Set last_login to current timestamp or use existing one if available
            last_login = user_data.get("last_login", int(time.time()))
            if metadata and metadata.get("original_last_active"):
                last_login = metadata["original_last_active"]
            
            # Connect to the database
            conn = sqlite3.connect(self._db_path)
            cursor = conn.cursor()
            
            # Check if user exists
            cursor.execute("SELECT email FROM login_users WHERE email = ?", (email,))
            user_exists = cursor.fetchone() is not None
            
            if user_exists:
                # Only update if existing last_login is older than the new one
                cursor.execute("SELECT last_login FROM login_users WHERE email = ?", (email,))
                existing_last_login = cursor.fetchone()[0]
                
                if not existing_last_login or existing_last_login < last_login:
                    # Update existing user
                    cursor.execute('''
                        UPDATE login_users
                        SET username = ?,
                            role = ?,
                            last_login = ?,
                            user_type = ?,
                            access = ?,
                            source_db = ?,
                            metadata = ?
                        WHERE email = ?
                    ''', (
                        username,
                        role,
                        last_login,
                        user_type,
                        access,
                        source_db,
                        json.dumps(metadata),
                        email
                    ))
                    logger.info(f"Updated login record for user {email}")
            else:
                # Insert new user
                cursor.execute('''
                    INSERT INTO login_users (
                        email,
                        username,
                        role,
                        last_login,
                        user_type,
                        access,
                        source_db,
                        metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    email,
                    username,
                    role,
                    last_login,
                    user_type,
                    access,
                    source_db,
                    json.dumps(metadata)
                ))
                logger.info(f"Created new login record for user {email}")
            
            conn.commit()
            conn.close()
            
            return True
        except Exception as e:
            logger.error(f"Error recording login for user {user_data.get('email')}: {str(e)}")
            return False 