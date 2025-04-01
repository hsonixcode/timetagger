"""
User management functionality for TimeTagger.

This module provides functionality to retrieve and manage users in TimeTagger,
including both local users and Azure users.
"""

import os
import logging
from typing import Dict, List, Optional, Any
from pathlib import Path
import time
import json

from sqlalchemy.orm import Session
from sqlalchemy import create_engine, text

from timetagger.server._utils import ROOT_USER_DIR, filename2user
from timetagger.server.db_utils import get_session, get_engine
from timetagger.server.db_utils import Record, Settings, UserInfo

logger = logging.getLogger("timetagger.multiuser")

class UserManager:
    """
    Manages users in the TimeTagger application.
    Provides functionality to retrieve users from the database.
    """
    
    def __init__(self):
        """
        Initialize the UserManager.
        """
        self._user_dir = ROOT_USER_DIR
        self._engine = get_engine()
        
    def _is_azure_user(self, session, username):
        """
        Determine if a user is an Azure AD user by examining database settings.
        
        Args:
            session: The SQLAlchemy session
            username: The username being checked
            
        Returns:
            tuple: (is_azure_user, user_info) where user_info contains details if found
        """
        try:
            # Initialize user info
            user_info = {
                "email": username if '@' in username else None,
                "display_name": username,
                "role": "user",
                "is_admin": False,
                "last_login": None
            }
            
            # Query settings for this user
            settings_records = session.query(Settings).filter_by(username=username).all()
            settings = [{c.name: getattr(record, c.name) for c in record.__table__.columns} for record in settings_records]
                
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
                user = login_tracker.get_user_by_email(username)
                
                # If we didn't find a user with the username as email, try with a constructed email
                if not user and "@" not in username:
                    email_guess = f"{username}@outlook.com"
                    user = login_tracker.get_user_by_email(email_guess)
                
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
            
            # Get list of unique usernames from the PostgreSQL database
            session = get_session()
            try:
                # Get distinct usernames from all tables
                usernames = set()
                
                # Query usernames from Records table
                records_usernames = session.query(Record.username).distinct().all()
                usernames.update([r[0] for r in records_usernames])
                
                # Query usernames from Settings table
                settings_usernames = session.query(Settings.username).distinct().all()
                usernames.update([s[0] for s in settings_usernames])
                
                # Query usernames from UserInfo table
                userinfo_usernames = session.query(UserInfo.username).distinct().all()
                usernames.update([u[0] for u in userinfo_usernames])
                
                logger.info(f"Found {len(usernames)} unique usernames in the database")
                
                # Process each username
                for username in usernames:
                    user_data = {
                        "username": username,
                        "email": username if '@' in username else None,
                        "display_name": username,
                        "is_allowed": True,
                        "role": "user",
                        "last_active": None
                    }
                    
                    # Get the last active time from records
                    last_record = session.query(Record).filter_by(username=username).order_by(Record.st.desc()).first()
                    if last_record:
                        user_data["last_active"] = getattr(last_record, "st")
                    
                    # Check if user is Azure user
                    is_azure, user_info = self._is_azure_user(session, username)
                    
                    # Update user data with Azure info if available
                    if user_info:
                        user_data.update({
                            "email": user_info.get("email", user_data["email"]),
                            "display_name": user_info.get("display_name", user_data["display_name"]),
                            "role": user_info.get("role", user_data["role"])
                        })
                    
                    # Set the source based on Azure check
                    user_data["source"] = "azure" if is_azure else "local"
                    
                    # Update with info from central database if available
                    if username in central_db_users:
                        central_info = central_db_users[username]
                        user_data.update({
                            "email": central_info.get("email", user_data["email"]),
                            "role": central_info.get("role", user_data["role"]),
                            "is_allowed": central_info.get("access") != "not allowed",
                            "source": central_info.get("user_type", user_data["source"])
                        })
                    elif user_data.get("email") and user_data["email"] in central_db_users:
                        central_info = central_db_users[user_data["email"]]
                        user_data.update({
                            "role": central_info.get("role", user_data["role"]),
                            "is_allowed": central_info.get("access") != "not allowed",
                            "source": central_info.get("user_type", user_data["source"])
                        })
                    
                    all_users.append(user_data)
                    
            finally:
                session.close()
                
            # Add users from central database that might not have database entries
            for username, user_info in central_db_users.items():
                if not any(u["username"] == username for u in all_users) and not any(u["email"] == username for u in all_users):
                    user_data = {
                        "username": username,
                        "email": user_info.get("email", username),
                        "display_name": user_info.get("username", username),
                        "role": user_info.get("role", "user"),
                        "is_allowed": user_info.get("access") != "not allowed",
                        "source": user_info.get("user_type", "unknown"),
                        "last_active": user_info.get("last_login")
                    }
                    all_users.append(user_data)
            
            # Log the results
            logger.info(f"Found {len(all_users)} total users")
            logger.info(f"Local users: {len([u for u in all_users if u.get('source') == 'local'])}")
            logger.info(f"Azure users: {len([u for u in all_users if u.get('source') == 'azure'])}")
            
            return all_users
            
        except Exception as e:
            logger.error(f"Error getting all users: {str(e)}")
            return []
    
    def get_local_users(self) -> List[Dict[str, Any]]:
        """Get all local (non-Azure) users."""
        all_users = self.get_all_users_classified()
        return [user for user in all_users if user.get("source") == "local"]
    
    def get_azure_users(self) -> List[Dict[str, Any]]:
        """Get all Azure AD users."""
        all_users = self.get_all_users_classified()
        return [user for user in all_users if user.get("source") == "azure"]
    
    def get_all_users(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get all users organized by type (local and Azure).
        
        Returns:
            Dict with keys 'local_users' and 'azure_users', each containing a list of user dicts.
        """
        all_users = self.get_all_users_classified()
        
        # Separate users by type
        local_users = [user for user in all_users if user.get("source") == "local"]
        azure_users = [user for user in all_users if user.get("source") == "azure"]
        
        # Sort users by last active time, most recent first
        local_users.sort(key=lambda u: u.get("last_active", 0) or 0, reverse=True)
        azure_users.sort(key=lambda u: u.get("last_active", 0) or 0, reverse=True)
        
        # Format the return data
        return {
            "local_users": local_users,
            "azure_users": azure_users,
            "all_users": all_users,
            "total_count": len(all_users),
            "local_count": len(local_users),
            "azure_count": len(azure_users)
        }
    
    async def update_user_access(self, username: str, is_allowed: bool, role: str = None) -> bool:
        """
        Update a user's access status and role.
        
        Args:
            username: The username or email of the user to update
            is_allowed: Whether the user is allowed to access the system
            role: Optional new role to assign to the user
            
        Returns:
            bool: True if the update was successful, False otherwise
        """
        # First try to update in the login database
        try:
            from .login_tracker import LoginTracker
            tracker = LoginTracker()
            
            # Update access status
            access_updated = tracker.update_user_access(username, is_allowed)
            
            # Update role if specified
            role_updated = True
            if role:
                role_updated = tracker.update_user_role(username, role)
            
            if access_updated or role_updated:
                logger.info(f"Updated user {username}: access={is_allowed}, role={role}")
                return True
                
        except Exception as e:
            logger.error(f"Error updating user access in login database: {str(e)}")
        
        # If updating in login database failed, try to update in the PostgreSQL database directly
        try:
            session = get_session()
            try:
                # Look up user in Settings table to make sure they exist
                user_settings = session.query(Settings).filter_by(username=username).first()
                
                if not user_settings:
                    logger.warning(f"User {username} not found in database")
                    return False
                
                # Update user settings
                # Find or create user_info setting
                user_info_setting = session.query(Settings).filter_by(
                    username=username, 
                    key="user_info"
                ).first()
                
                if user_info_setting:
                    # Update existing setting
                    user_info = getattr(user_info_setting, "value", {}) or {}
                    if role:
                        user_info["role"] = role
                    user_info["is_allowed"] = is_allowed
                    
                    setattr(user_info_setting, "value", user_info)
                    setattr(user_info_setting, "mt", int(time.time()))
                    setattr(user_info_setting, "st", time.time())
                else:
                    # Create new setting
                    user_info = {
                        "role": role or "user",
                        "is_allowed": is_allowed
                    }
                    
                    new_setting = Settings(
                        username=username,
                        key="user_info",
                        value=user_info,
                        mt=int(time.time()),
                        st=time.time()
                    )
                    session.add(new_setting)
                
                session.commit()
                logger.info(f"Updated user {username} access in database: access={is_allowed}, role={role}")
                return True
                
            finally:
                session.close()
                
        except Exception as e:
            logger.error(f"Error updating user access in user database: {str(e)}")
            return False 