"""
User management functionality for TimeTagger.

This module provides functionality to retrieve and manage users in TimeTagger,
including both local users and Azure users.
"""

import os
import logging
import sqlite3
from typing import Dict, List, Optional, Any
from pathlib import Path
import time
import json

from timetagger.server._utils import ROOT_USER_DIR, filename2user
from itemdb import ItemDB

logger = logging.getLogger("timetagger.multiuser")

class UserManager:
    """
    Manages users in the TimeTagger application.
    Provides functionality to retrieve users from the SQLite databases.
    """
    
    def __init__(self):
        """
        Initialize the UserManager.
        """
        self._user_dir = ROOT_USER_DIR
        
    def _is_azure_user(self, db, username):
        """
        Determine if a user is an Azure AD user by examining database settings.
        
        Args:
            db: The ItemDB database object
            username: The username being checked
            
        Returns:
            tuple: (is_azure_user, user_info) where user_info contains details if found
        """
        try:
            with db:
                settings = db.select_all("settings")
                
                # Initialize user info
                user_info = {
                    "email": username if '@' in username else None,
                    "display_name": username,
                    "role": "user",
                    "is_admin": False,
                    "last_login": None
                }
                
                # First look for direct azure_info
                for setting in settings:
                    if setting.get("key") == "azure_info":
                        azure_info = setting.get("value", {})
                        if azure_info:
                            user_info.update({
                                "email": azure_info.get("email", user_info["email"]),
                                "display_name": azure_info.get("display_name", user_info["display_name"]),
                                "role": azure_info.get("role", user_info["role"]),
                                "last_login": azure_info.get("last_login", user_info["last_login"])
                            })
                            return True, user_info
                
                # Now look for auth_info and other Azure-related information
                contains_azure_token = False
                
                for setting in settings:
                    # Look for auth token info as a backup indicator of Azure login
                    if setting.get("key") == "auth_info":
                        auth_info = setting.get("value", {})
                        if auth_info and auth_info.get("auth_type") == "azure":
                            user_info.update({
                                "email": auth_info.get("email", user_info["email"]),
                                "display_name": auth_info.get("name", user_info["display_name"]),
                                "role": auth_info.get("role", user_info["role"])
                            })
                            contains_azure_token = True
                    
                    # Also check for any webtoken_azure setting which would indicate Azure login
                    if setting.get("key") == "webtoken_azure" or setting.get("key") == "timetagger_webtoken_azure":
                        contains_azure_token = True
                
                if contains_azure_token:
                    logger.info(f"User {username} identified as Azure user based on auth settings")
                    return True, user_info
                
                # Check for user_info with Azure indicators
                for setting in settings:
                    if setting.get("key") == "user_info":
                        user_data = setting.get("value", {})
                        if user_data:
                            # Update user info with available data
                            user_info.update({
                                "email": user_data.get("email", user_info["email"]),
                                "display_name": user_data.get("display_name", user_info["display_name"]),
                                "role": user_data.get("role", user_info["role"])
                            })
                            
                            # Check if this is explicitly marked as an Azure user
                            if user_data.get("auth_type") == "azure" or user_data.get("user_type") == "azure":
                                logger.info(f"User {username} identified as Azure user from user_info")
                                return True, user_info
                
                # Last resort: check email domain
                email = user_info.get("email")
                if email and "@" in email:
                    domain = email.split("@")[1].lower()
                    # Common corporate/enterprise domains that might use Azure AD
                    azure_domains = ["nrgnr.com", "outlook.com", "microsoft.com", "live.com", "hotmail.com"]
                    if domain in azure_domains:
                        # For domains that suggest Azure, log and return true
                        logger.info(f"User {username} identified as Azure user based on email domain {domain}")
                        return True, user_info
                
                # Check if the username itself suggests Azure (like email address)
                if "@" in username and any(domain in username.lower() for domain in ["outlook.com", "microsoft.com", "live.com", "hotmail.com"]):
                    logger.info(f"User {username} identified as Azure user based on username format")
                    user_info["email"] = username  # Ensure email is set
                    return True, user_info
                
                # If all else fails, check the login database as a fallback
                try:
                    from .login_tracker import LoginTracker
                    login_tracker = LoginTracker()
                    
                    # Try matching by username first
                    user = login_tracker.get_login_by_email(username)
                    
                    # If we didn't find a user with the username as email, try with a constructed email
                    if not user and "@" not in username:
                        email_guess = f"{username}@outlook.com"
                        user = login_tracker.get_login_by_email(email_guess)
                    
                    if user and user.get("user_type") == "azure":
                        logger.info(f"User {username} identified as Azure user from login database")
                        user_info.update({
                            "email": user.get("email", user_info["email"]),
                            "role": user.get("role", user_info["role"]),
                            "last_login": user.get("last_login", user_info["last_login"])
                        })
                        return True, user_info
                except Exception as e:
                    logger.debug(f"Error checking login database for user {username}: {str(e)}")
                
                return False, user_info
        except Exception as e:
            logger.debug(f"Error checking if user {username} is an Azure user: {str(e)}")
            return False, {}
    
    def get_all_users_classified(self) -> List[Dict[str, Any]]:
        """
        Get all users from the database and classify them as either local or Azure.
        This is a more reliable approach than separating the queries.
        
        Returns:
            List of user dictionaries with all attributes including source.
        """
        all_users = []
        user_path = Path(self._user_dir)
        
        if not user_path.exists():
            logger.warning(f"User directory does not exist: {self._user_dir}")
            return []
        
        try:
            # Before scanning individual user databases, check the central login database
            # This will help us identify Azure users who might have logged in but don't have DB files
            central_db_users = {}
            try:
                from .login_tracker import LoginTracker
                
                # Get all login entries
                login_tracker = LoginTracker()
                all_logins = login_tracker.get_all_logins()
                
                # Create a map for quick lookup by username and email
                for login in all_logins:
                    email = login.get("email")
                    username = login.get("username")
                    
                    if email:
                        central_db_users[email] = login
                    if username and username != email:
                        central_db_users[username] = login
                
                logger.info(f"Found {len(central_db_users)} users in central login database")
            
            except Exception as e:
                logger.error(f"Error accessing central login database: {str(e)}")
                central_db_users = {}
            
            # Get list of users from the database files in the user directory
            for db_file in user_path.glob("*.db"):
                try:
                    username = filename2user(db_file)
                    # Skip the default user if it exists
                    if username == 'defaultuser':
                        continue
                    
                    # Get file metadata for 'last active' information (fallback)
                    last_active = int(db_file.stat().st_mtime)
                    
                    # Open the database
                    db = ItemDB(str(db_file))
                    
                    # Check if this is an Azure user
                    is_azure_user, user_info = self._is_azure_user(db, username)
                    
                    # Check central database for additional information
                    central_info = central_db_users.get(username) or central_db_users.get(user_info.get("email", ""))
                    if central_info:
                        # If central database says this is an Azure user, override local detection
                        if central_info.get("user_type") == "azure":
                            is_azure_user = True
                            logger.info(f"User {username} identified as Azure user from central database")
                        
                        # Update user info with central database data
                        user_info.update({
                            "email": central_info.get("email", user_info.get("email")),
                            "role": central_info.get("role", user_info.get("role")),
                            "last_login": central_info.get("last_login", user_info.get("last_login"))
                        })
                    
                    # Common user data
                    user_data = {
                        "username": username,
                        "email": user_info.get("email", username if '@' in username else None),
                        "display_name": user_info.get("display_name", username),
                        "role": user_info.get("role", "user"),
                        "last_active": user_info.get("last_login", last_active),
                        "auth_type": "azure" if is_azure_user else "local",
                        "source": "azure" if is_azure_user else "local"
                    }
                    
                    # Determine if the user is allowed to access the system
                    is_allowed = True  # Default to allowed
                    
                    # Use central database info if available
                    if central_info:
                        is_allowed = central_info.get("access") != "not allowed"
                    else:
                        # For local users - assume all users with DB files are allowed
                        # For Azure users - check for is_allowed field or default to true
                        with db:
                            settings = db.select_all("settings")
                            for setting in settings:
                                if setting.get("key") == "azure_info":
                                    azure_info = setting.get("value", {})
                                    if azure_info and "is_allowed" in azure_info:
                                        is_allowed = bool(azure_info.get("is_allowed", True))
                                        break
                                elif setting.get("key") == "user_info":
                                    info = setting.get("value", {})
                                    if "is_allowed" in info:
                                        is_allowed = bool(info.get("is_allowed", True))
                                        break
                    
                    user_data["is_allowed"] = is_allowed
                    
                    # Ensure last_active has a valid timestamp value
                    if user_data["last_active"] is None or user_data["last_active"] == 0:
                        # Use current time if file time is not available
                        user_data["last_active"] = int(time.time())
                    
                    all_users.append(user_data)
                except Exception as e:
                    logger.error(f"Error processing user DB file {db_file}: {str(e)}")
            
            # Add Azure users from central database who don't have DB files
            for email, user in central_db_users.items():
                if '@' not in email:
                    continue  # Skip non-email keys
                
                username = user.get("username", email.split('@')[0])
                
                # Check if this user is already in our list
                if any(u["username"] == username or u.get("email") == email for u in all_users):
                    continue
                
                # Only add Azure users who don't have DB files
                if user.get("user_type") == "azure":
                    user_data = {
                        "username": username,
                        "email": email,
                        "display_name": username,
                        "role": user.get("role", "user"),
                        "last_active": user.get("last_login", int(time.time())),
                        "auth_type": "azure",
                        "source": "azure",
                        "is_allowed": user.get("access") != "not allowed"
                    }
                    
                    # Try to extract metadata
                    if user.get("metadata"):
                        metadata = user.get("metadata", {})
                        if isinstance(metadata, dict):
                            user_data["display_name"] = metadata.get("display_name", user_data["display_name"])
                    
                    all_users.append(user_data)
                    logger.info(f"Added Azure user {username} from central database (no DB file)")
            
            # Sort by username for consistent order
            all_users.sort(key=lambda u: u["username"])
            
            # Handle admin role - if no admin is found, set the first user as admin
            if all_users and not any(user["role"] == "admin" for user in all_users):
                all_users[0]["role"] = "admin"
            
            return all_users
        except Exception as e:
            logger.error(f"Error getting all users: {str(e)}")
            return []
    
    def get_local_users(self) -> List[Dict[str, Any]]:
        """
        Get all local users from the timetagger user directory.
        Users are identified as local if they don't have azure_info.
        
        Returns:
            List of user dictionaries with name and role.
        """
        all_users = self.get_all_users_classified()
        return [user for user in all_users if user["source"] == "local"]
    
    def get_azure_users(self) -> List[Dict[str, Any]]:
        """
        Get Azure users from the user databases.
        Users are identified as Azure users based on authentication data.
        
        Returns:
            List of user dictionaries with name, email, and role.
        """
        all_users = self.get_all_users_classified()
        return [user for user in all_users if user["source"] == "azure"]
    
    def get_all_users(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get both local and Azure users.
        
        Returns:
            Dictionary with two keys: 'local_users' and 'azure_users',
            each containing a list of user dictionaries.
        """
        all_users = self.get_all_users_classified()
        
        # If there are no users found, add some test Azure users for development purposes
        if not all_users:
            import time
            current_time = int(time.time())
            
            # Add test Azure users only
            test_azure_users = [
                {
                    "username": "azure_admin",
                    "email": "azure_admin@outlook.com",
                    "display_name": "Azure Admin",
                    "role": "admin",
                    "last_active": current_time,
                    "auth_type": "azure",
                    "source": "azure",
                    "is_allowed": True
                },
                {
                    "username": "azure_user",
                    "email": "azure_user@outlook.com",
                    "display_name": "Azure User",
                    "role": "user",
                    "last_active": current_time - 3600,  # 1 hour ago
                    "auth_type": "azure",
                    "source": "azure",
                    "is_allowed": True
                },
                {
                    "username": "azure_inactive",
                    "email": "azure_inactive@outlook.com",
                    "display_name": "Azure Inactive",
                    "role": "user",
                    "last_active": current_time - 86400 * 10,  # 10 days ago
                    "auth_type": "azure",
                    "source": "azure",
                    "is_allowed": False
                },
                {
                    "username": "azure_new",
                    "email": "azure_new@outlook.com",
                    "display_name": "New Azure User",
                    "role": "user",
                    "last_active": current_time - 1800,  # 30 minutes ago
                    "auth_type": "azure",
                    "source": "azure",
                    "is_allowed": True
                },
                {
                    "username": "azure_guest",
                    "email": "azure_guest@outlook.com",
                    "display_name": "Azure Guest",
                    "role": "guest",
                    "last_active": current_time - 7200,  # 2 hours ago
                    "auth_type": "azure",
                    "source": "azure",
                    "is_allowed": False
                }
            ]
            
            logger.info("No real users found, using test Azure user data")
            return {
                "local_users": [],
                "azure_users": test_azure_users
            }
        
        return {
            "local_users": [user for user in all_users if user["source"] == "local"],
            "azure_users": [user for user in all_users if user["source"] == "azure"]
        }
        
    async def update_user_access(self, username: str, is_allowed: bool) -> bool:
        """
        Update a user's access status.
        
        Args:
            username: The username of the user to update.
            is_allowed: Whether the user should be allowed access.
            
        Returns:
            bool: True if the update was successful, False otherwise.
        """
        logger.info(f"Updating access for user {username} to {is_allowed}")
        
        # In a real implementation, we would update the user's access status in the database.
        # For this prototype, we'll simulate the update for our test users.
        
        # If using real database:
        user_path = Path(self._user_dir)
        if not user_path.exists():
            logger.warning(f"User directory does not exist: {self._user_dir}")
            return False
        
        try:
            # Find the user's database file
            db_files = list(user_path.glob(f"*{username}*.db"))
            
            if not db_files:
                # For test users, we'll simulate the update
                all_users = self.get_all_users()
                found = False
                
                # Check in Azure users
                for user in all_users["azure_users"]:
                    if user["username"] == username:
                        user["is_allowed"] = is_allowed
                        found = True
                        break
                
                # Return success for test users
                if found:
                    logger.info(f"Updated access for test user {username}")
                    return True
                
                logger.warning(f"User {username} not found")
                return False
            
            # For real users in database:
            db_file = db_files[0]
            db = ItemDB(str(db_file))
            
            with db:
                # First check if this is an Azure user
                is_azure_user, _ = self._is_azure_user(db, username)
                
                if is_azure_user:
                    # Look for azure_info setting
                    for setting in db.select_all("settings"):
                        if setting.get("key") == "azure_info":
                            azure_info = setting.get("value", {}) or {}
                            azure_info["is_allowed"] = is_allowed
                            
                            # Update the setting
                            setting["value"] = azure_info
                            db.put("settings", setting)
                            logger.info(f"Updated azure_info for user {username}")
                            return True
                    
                    # If no azure_info, look for user_info setting
                    for setting in db.select_all("settings"):
                        if setting.get("key") == "user_info":
                            user_info = setting.get("value", {}) or {}
                            user_info["is_allowed"] = is_allowed
                            
                            # Update the setting
                            setting["value"] = user_info
                            db.put("settings", setting)
                            logger.info(f"Updated user_info for user {username}")
                            return True
                    
                    # If no user_info, create a new azure_info setting
                    import time
                    st = time.time()
                    
                    db.put_one("settings", key="azure_info", st=st, mt=st, value={
                        "is_allowed": is_allowed
                    })
                    
                    logger.info(f"Created new azure_info for user {username}")
                    return True
                else:
                    # For local users, we generally always allow access
                    # But we'll still update for consistency if needed
                    for setting in db.select_all("settings"):
                        if setting.get("key") == "user_info":
                            user_info = setting.get("value", {}) or {}
                            user_info["is_allowed"] = is_allowed
                            
                            # Update the setting
                            setting["value"] = user_info
                            db.put("settings", setting)
                            logger.info(f"Updated user_info for local user {username}")
                            return True
                    
                    # If no user_info, create a new one
                    import time
                    st = time.time()
                    
                    db.put_one("settings", key="user_info", st=st, mt=st, value={
                        "is_allowed": is_allowed
                    })
                    
                    logger.info(f"Created new user_info for local user {username}")
                    return True
        
        except Exception as e:
            logger.error(f"Error updating user access: {str(e)}")
            return False 