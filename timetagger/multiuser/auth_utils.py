"""
Authentication utilities for TimeTagger multiuser functionality.

This module provides utilities for authentication-related operations,
particularly for consistent checking of user roles and permissions.
"""

import logging
import json
import base64
from typing import Dict, Any, Optional, Tuple
import asyncio

logger = logging.getLogger("timetagger.multiuser")

async def check_admin_status(auth_info: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Standardized method to check if a user has admin status.
    Checks multiple sources in a consistent order:
    
    1. First from the login database (most authoritative source)
    2. Then from the auth_info directly
    3. Then from the JWT token payload
    4. Finally from the credentials file (first user in credentials)
    
    Args:
        auth_info: Authentication information dictionary containing username and token
        
    Returns:
        Tuple of (is_admin: bool, source: str) where source indicates where the admin status was determined
    """
    username = auth_info.get("username")
    if not username:
        logger.warning("No username provided in auth_info for admin check")
        return False, "no_username"
    
    # 1. Check from login database first (most authoritative)
    try:
        from .login_tracker import LoginTracker
        tracker = LoginTracker()
        user = tracker.get_login_by_email(username)
        
        if user:
            is_admin = user.get("role") == "admin"
            if is_admin:
                logger.info(f"User {username} admin status (true) determined from login database")
                return True, "login_db"
            elif user.get("role") == "user":
                logger.info(f"User {username} admin status (false) determined from login database")
                return False, "login_db"
    except Exception as e:
        logger.error(f"Error checking admin status from login database: {e}")
    
    # 2. Check from auth_info directly
    is_admin = auth_info.get("is_admin", False)
    if is_admin:
        logger.info(f"User {username} admin status (true) determined from auth_info")
        return True, "auth_info"
    
    # 3. Check from JWT token if available
    if 'token' in auth_info:
        try:
            token_parts = auth_info['token'].split('.')
            if len(token_parts) >= 2:
                # Ensure correct padding for base64 decoding
                payload_b64 = token_parts[1]
                payload_b64 += '=' * (-len(payload_b64) % 4)
                # Decode the payload and extract the is_admin flag
                token_payload = json.loads(base64.urlsafe_b64decode(payload_b64))
                is_admin = token_payload.get('is_admin', False)
                if is_admin:
                    logger.info(f"User {username} admin status (true) determined from JWT token")
                    return True, "token_payload"
        except Exception as e:
            logger.error(f"Error extracting admin status from token: {e}")
    
    # 4. Check if it's the first user in credentials file
    try:
        from .. import config
        credentials = config.credentials.replace(";", ",").split(",")
        is_first_user = bool(credentials and credentials[0].startswith(username + ":"))
        if is_first_user:
            logger.info(f"User {username} admin status (true) determined from credentials file (first user)")
            return True, "credentials_file"
    except Exception as e:
        logger.error(f"Error checking credentials file: {e}")
    
    # Default to not an admin if all checks fail
    logger.info(f"User {username} admin status (false) after all checks")
    return False, "default"

def check_admin_status_sync(auth_info: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Synchronous version of check_admin_status that doesn't use asyncio.run(),
    avoiding issues with existing event loops.
    
    Args:
        auth_info: Authentication information dictionary containing username and token
        
    Returns:
        Tuple of (is_admin: bool, source: str)
    """
    username = auth_info.get("username")
    if not username:
        logger.warning("No username provided in auth_info for admin check")
        return False, "no_username"
    
    # 1. Check from login database first (most authoritative)
    try:
        from .login_tracker import LoginTracker
        tracker = LoginTracker()
        user = tracker.get_login_by_email(username)
        
        if user:
            is_admin = user.get("role") == "admin"
            if is_admin:
                logger.info(f"User {username} admin status (true) determined from login database")
                return True, "login_db"
            elif user.get("role") == "user":
                logger.info(f"User {username} admin status (false) determined from login database")
                return False, "login_db"
    except Exception as e:
        logger.error(f"Error checking admin status from login database: {e}")
    
    # 2. Check from auth_info directly
    is_admin = auth_info.get("is_admin", False)
    if is_admin:
        logger.info(f"User {username} admin status (true) determined from auth_info")
        return True, "auth_info"
    
    # 3. Check from JWT token if available
    if 'token' in auth_info:
        try:
            token_parts = auth_info['token'].split('.')
            if len(token_parts) >= 2:
                # Ensure correct padding for base64 decoding
                payload_b64 = token_parts[1]
                payload_b64 += '=' * (-len(payload_b64) % 4)
                # Decode the payload and extract the is_admin flag
                token_payload = json.loads(base64.urlsafe_b64decode(payload_b64))
                is_admin = token_payload.get('is_admin', False)
                if is_admin:
                    logger.info(f"User {username} admin status (true) determined from JWT token")
                    return True, "token_payload"
        except Exception as e:
            logger.error(f"Error extracting admin status from token: {e}")
    
    # 4. Check if it's the first user in credentials file
    try:
        from .. import config
        credentials = config.credentials.replace(";", ",").split(",")
        is_first_user = bool(credentials and credentials[0].startswith(username + ":"))
        if is_first_user:
            logger.info(f"User {username} admin status (true) determined from credentials file (first user)")
            return True, "credentials_file"
    except Exception as e:
        logger.error(f"Error checking credentials file: {e}")
    
    # Default to not an admin if all checks fail
    logger.info(f"User {username} admin status (false) after all checks")
    return False, "default"

def invalidate_user_token(username: str) -> bool:
    """
    Invalidate a user's token by updating their token seed.
    This forces them to get a new token on next login/token refresh.
    
    Args:
        username: The username or email of the user
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        from timetagger.server._apiserver import _get_token_seed_from_db
        from timetagger.server._utils import user2filename
        import itemdb
        
        # Open the user's database
        dbname = user2filename(username)
        db = itemdb.ItemDB(dbname)
        
        # Reset both webtoken and apitoken seeds
        webtoken_reset = _get_token_seed_from_db(db, "webtoken", True)
        apitoken_reset = _get_token_seed_from_db(db, "apitoken", True)
        
        logger.info(f"Successfully invalidated tokens for user {username}")
        return True
    except Exception as e:
        logger.error(f"Failed to invalidate tokens for user {username}: {e}")
        return False 