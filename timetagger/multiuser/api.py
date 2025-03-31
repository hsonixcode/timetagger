"""
API endpoints for multiuser functionality.

This module provides API endpoints for the multiuser functionality,
including the /api/users endpoint.
"""

import logging
from typing import Dict, Any, Tuple, List
import json
import time

from .user import UserManager
from .login_tracker import LoginTracker

logger = logging.getLogger("timetagger.multiuser")

async def get_users(request, auth_info) -> Tuple[int, Dict[str, str], Dict[str, Any]]:
    """
    API endpoint handler to get all users.
    
    Args:
        request: The HTTP request object.
        auth_info: Authentication information for the current user.
        
    Returns:
        Tuple of (status_code, headers, response_body).
    """
    # Check if user is authenticated
    if not auth_info:
        logger.warning("Unauthenticated access attempt to users endpoint")
        return 401, {}, {"error": "Authentication required"}
    
    # Optional: Check if user has admin privileges for better security
    # is_admin = auth_info.get("is_admin", False)
    # if not is_admin:
    #     logger.warning(f"Non-admin user {auth_info.get('username')} attempted to access users endpoint")
    #     return 403, {}, {"error": "Admin privileges required"}
    
    try:
        # Get users from the UserManager
        user_manager = UserManager()
        users = user_manager.get_all_users()
        
        # Return the users
        return 200, {"content-type": "application/json"}, users
    except Exception as e:
        logger.error(f"Error retrieving users: {str(e)}")
        return 500, {}, {"error": f"Server error: {str(e)}"}

async def get_login_users(request, auth_info) -> Tuple[int, Dict[str, str], Dict[str, Any]]:
    """
    API endpoint handler to get login users from the central database.
    
    Args:
        request: The HTTP request object.
        auth_info: Authentication information for the current user.
        
    Returns:
        Tuple of (status_code, headers, response_body).
    """
    # Check if user is authenticated
    if not auth_info:
        logger.warning("Unauthenticated access attempt to login-users endpoint")
        return 401, {}, {"error": "Authentication required"}
    
    # Check if user has admin privileges
    is_admin = auth_info.get("is_admin", False)
    if not is_admin:
        logger.warning(f"Non-admin user {auth_info.get('username')} attempted to access login-users endpoint")
        return 403, {}, {"error": "Admin privileges required"}
    
    try:
        # Get query parameters for filtering
        # Check if request has query attribute (handle both asgineer and regular HTTP request objects)
        query_params = {}
        try:
            if hasattr(request, 'query'):
                query_params = request.query
            elif hasattr(request, 'querydict'):
                query_params = request.querydict
            else:
                # For URL path parameters (e.g., /login-users/1)
                path = request.path if hasattr(request, 'path') else ""
                if path and '/' in path:
                    path_parts = path.split('/')
                    if len(path_parts) > 1 and path_parts[-1].isdigit():
                        # This is a path parameter for an ID
                        logger.info(f"Path parameter detected: {path_parts[-1]}")
                
                logger.warning("Request object does not have query attribute. Using empty query parameters.")
        except Exception as e:
            logger.error(f"Error accessing query parameters: {str(e)}")
            query_params = {}
        
        # Extract filter parameters
        user_type = query_params.get("user_type")
        if user_type and user_type not in ("local", "azure"):
            return 400, {}, {"error": "Invalid user_type parameter. Must be 'local' or 'azure'."}
        
        role = query_params.get("role")
        access = query_params.get("access")
        if access and access not in ("allowed", "not allowed"):
            return 400, {}, {"error": "Invalid access parameter. Must be 'allowed' or 'not allowed'."}
        
        # Get users from the LoginTracker
        login_tracker = LoginTracker()
        users = login_tracker.get_all_logins(
            user_type=user_type,
            role=role,
            access=access
        )
        
        # Return the users
        return 200, {"content-type": "application/json"}, {"login_users": users}
    except Exception as e:
        logger.error(f"Error retrieving login users: {str(e)}")
        return 500, {}, {"error": f"Server error: {str(e)}"}

async def backfill_login_database(request, auth_info) -> Tuple[int, Dict[str, str], Dict[str, Any]]:
    """
    API endpoint handler to backfill the login database from existing user databases.
    
    Args:
        request: The HTTP request object.
        auth_info: Authentication information for the current user.
        
    Returns:
        Tuple of (status_code, headers, response_body).
    """
    # Check if user is authenticated
    if not auth_info:
        logger.warning("Unauthenticated access attempt to backfill-login-database endpoint")
        return 401, {}, {"error": "Authentication required"}
    
    # Check if user has admin privileges
    is_admin = auth_info.get("is_admin", False)
    if not is_admin:
        logger.warning(f"Non-admin user {auth_info.get('username')} attempted to access backfill-login-database endpoint")
        return 403, {}, {"error": "Admin privileges required"}
    
    try:
        # Run the backfill operation
        login_tracker = LoginTracker()
        success_count, error_count = login_tracker.backfill_from_user_databases()
        
        # Return the results
        return 200, {"content-type": "application/json"}, {
            "success": True,
            "message": f"Backfill operation completed successfully. Processed {success_count + error_count} users.",
            "details": {
                "success_count": success_count,
                "error_count": error_count
            }
        }
    except Exception as e:
        logger.error(f"Error during backfill operation: {str(e)}")
        return 500, {}, {"error": f"Server error: {str(e)}"}

async def update_user_access(request, auth_info) -> Tuple[int, Dict[str, str], Dict[str, Any]]:
    """
    API endpoint handler to update a user's access status.
    
    Args:
        request: The HTTP request object.
        auth_info: Authentication information for the current user.
        
    Returns:
        Tuple of (status_code, headers, response_body).
    """
    # Check if user is authenticated
    if not auth_info:
        logger.warning("Unauthenticated access attempt to update user access endpoint")
        return 401, {}, {"error": "Authentication required"}
    
    # Check if user has admin privileges
    if not auth_info.get("is_admin", False):
        logger.warning(f"Non-admin user {auth_info.get('username')} attempted to update user access")
        return 403, {}, {"error": "Admin privileges required"}
    
    try:
        # Get request body
        body = await request.get_json()
        
        # Validate request body
        username = body.get("username")
        is_allowed = body.get("is_allowed")
        
        if not username:
            return 400, {}, {"error": "Username is required"}
        
        if is_allowed is None:
            return 400, {}, {"error": "is_allowed is required"}
        
        # Update user access in the UserManager
        user_manager = UserManager()
        result = await user_manager.update_user_access(username, is_allowed)
        
        if not result:
            return 404, {}, {"error": f"User '{username}' not found"}
        
        # Also update the user in the central login database if it exists
        try:
            # First get the user to check if they exist in the login database
            login_tracker = LoginTracker()
            
            # Create login record - try to extract email from username
            email = username
            if '@' not in username:
                email = f"{username}@localhost"  # Fallback for local users without email
            
            user = login_tracker.get_login_by_email(email)
            
            if user:
                # User exists in login database, update access status
                user_data = {
                    "email": email,
                    "username": username,
                    "role": user.get("role", "user"),
                    "user_type": user.get("user_type", "local"),
                    "is_allowed": is_allowed,
                    "source_db": user.get("source_db", f"{username}.db"),
                    "metadata": user.get("metadata", {})
                }
                
                # Record the update
                await login_tracker.record_login(user_data)
                logger.info(f"Updated access status in central login database for user {email}")
        except Exception as e:
            # Log error but continue (this is not critical)
            logger.error(f"Error updating access status in central login database: {str(e)}")
        
        # Return success message
        return 200, {"content-type": "application/json"}, {
            "success": True,
            "message": f"Access for user '{username}' updated successfully."
        }
    except Exception as e:
        logger.error(f"Error updating user access: {str(e)}")
        return 500, {}, {"error": f"Server error: {str(e)}"}

async def search_users(request, auth_info) -> Tuple[int, Dict[str, str], Dict[str, Any]]:
    """
    API endpoint handler to search users.
    
    Args:
        request: The HTTP request object.
        auth_info: Authentication information for the current user.
        
    Returns:
        Tuple of (status_code, headers, response_body).
    """
    # Check if user is authenticated
    if not auth_info:
        logger.warning("Unauthenticated access attempt to users search endpoint")
        return 401, {}, {"error": "Authentication required"}
    
    try:
        # Get search query from request parameters
        query_params = {}
        try:
            if hasattr(request, 'query'):
                query_params = request.query
            elif hasattr(request, 'querydict'):
                query_params = request.querydict
            else:
                logger.warning("Request object does not have query attribute. Using empty query parameters.")
        except Exception as e:
            logger.error(f"Error accessing query parameters: {str(e)}")
            query_params = {}
            
        search_query = query_params.get("q", "").lower()
        if not search_query:
            return 400, {}, {"error": "Search query parameter 'q' is required"}
        
        # Get users from the UserManager
        user_manager = UserManager()
        all_users = user_manager.get_all_users()
        
        # Filter users based on search query
        filtered_local_users = _filter_users(all_users["local_users"], search_query)
        filtered_azure_users = _filter_users(all_users["azure_users"], search_query)
        
        # Return the filtered users
        return 200, {"content-type": "application/json"}, {
            "local_users": filtered_local_users,
            "azure_users": filtered_azure_users
        }
    except Exception as e:
        logger.error(f"Error searching users: {str(e)}")
        return 500, {}, {"error": f"Server error: {str(e)}"}

def _filter_users(users: List[Dict[str, Any]], query: str) -> List[Dict[str, Any]]:
    """
    Filter users based on a search query.
    
    Args:
        users: List of user dictionaries.
        query: Search query string.
        
    Returns:
        Filtered list of user dictionaries.
    """
    filtered = []
    for user in users:
        # Check if query matches any of the user fields
        if any(
            query in str(value).lower()
            for key, value in user.items()
            if value and key in ["username", "email", "display_name", "role"]
        ):
            filtered.append(user)
    return filtered

async def record_login_test(request, auth_info) -> Tuple[int, Dict[str, str], Dict[str, Any]]:
    """
    API endpoint handler to manually test login recording.
    
    Args:
        request: The HTTP request object.
        auth_info: Authentication information for the current user.
        
    Returns:
        Tuple of (status_code, headers, response_body).
    """
    # Check if user is authenticated
    if not auth_info:
        logger.warning("Unauthenticated access attempt to record_login_test endpoint")
        return 401, {}, {"error": "Authentication required"}
    
    # Check if user has admin privileges
    if not auth_info.get("is_admin", False):
        logger.warning(f"Non-admin user {auth_info.get('username')} attempted to access record_login_test endpoint")
        return 403, {}, {"error": "Admin privileges required"}
    
    try:
        # Get request body
        body = await request.get_json()
        
        # Validate required fields
        email = body.get("email")
        username = body.get("username")
        user_type = body.get("user_type", "azure")
        
        if not email:
            return 400, {}, {"error": "Email is required"}
        
        if not username:
            return 400, {}, {"error": "Username is required"}
        
        # Create user data object for login tracker
        user_data = {
            "email": email,
            "username": username,
            "role": body.get("role", "user"),
            "user_type": user_type,
            "is_allowed": body.get("is_allowed", True),
            "source_db": f"{username}.db",
            "metadata": body.get("metadata", {
                "test_record": True,
                "timestamp": int(time.time())
            })
        }
        
        # Record the login
        login_tracker = LoginTracker()
        success = await login_tracker.record_login(user_data)
        
        if not success:
            return 500, {}, {"error": "Failed to record login test"}
        
        # Check if the record was created
        user = login_tracker.get_login_by_email(email)
        
        if not user:
            return 404, {}, {"error": "User record not found after creation"}
        
        # Return success with the user data
        return 200, {"content-type": "application/json"}, {
            "success": True,
            "message": f"Test login record created for {username}",
            "user": user
        }
    except Exception as e:
        logger.error(f"Error recording login test: {str(e)}")
        return 500, {}, {"error": f"Server error: {str(e)}"}

async def debug_azure_users(request, auth_info) -> Tuple[int, Dict[str, str], Dict[str, Any]]:
    """
    API endpoint handler to debug Azure users in the central database.
    
    Args:
        request: The HTTP request object.
        auth_info: Authentication information for the current user.
        
    Returns:
        Tuple of (status_code, headers, response_body).
    """
    # Check if user is authenticated
    if not auth_info:
        logger.warning("Unauthenticated access attempt to debug_azure_users endpoint")
        return 401, {}, {"error": "Authentication required"}
    
    # Check if user has admin privileges
    is_admin = auth_info.get("is_admin", False)
    if not is_admin:
        logger.warning(f"Non-admin user {auth_info.get('username')} attempted to access debug_azure_users endpoint")
        return 403, {}, {"error": "Admin privileges required"}
    
    try:
        # Add request debugging info
        request_info = {
            "has_query": hasattr(request, "query"),
            "has_querydict": hasattr(request, "querydict"),
            "has_path": hasattr(request, "path"),
            "available_attrs": [attr for attr in dir(request) if not attr.startswith('_')]
        }
        
        # Get database info
        from pathlib import Path
        import sqlite3
        import os
        from timetagger.server._utils import ROOT_USER_DIR
        
        # Check if login database exists
        login_db_path = os.path.join(ROOT_USER_DIR, "login_users.db")
        login_db_exists = os.path.exists(login_db_path)
        
        debug_info = {
            "request_info": request_info,
            "login_db_exists": login_db_exists,
            "login_db_path": login_db_path,
            "azure_users": [],
            "local_users": [],
            "user_dirs": [],
            "db_files": []
        }
        
        # Scan user directories
        user_path = Path(ROOT_USER_DIR)
        if user_path.exists():
            debug_info["user_dirs"] = [str(d) for d in user_path.iterdir() if d.is_dir()]
            
            # Look for db files
            db_files = list(user_path.glob("*.db")) + list(user_path.glob("**/*.db"))
            debug_info["db_files"] = [str(f) for f in db_files]
        
        # If login database exists, check it directly
        if login_db_exists:
            try:
                # Connect to the database
                conn = sqlite3.connect(login_db_path)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                # Get all users
                cursor.execute("SELECT * FROM login_users")
                rows = cursor.fetchall()
                
                # Parse rows into dicts
                all_users = []
                for row in rows:
                    user_dict = dict(row)
                    
                    # Parse JSON metadata
                    try:
                        if user_dict.get("metadata"):
                            user_dict["metadata"] = json.loads(user_dict["metadata"])
                        else:
                            user_dict["metadata"] = {}
                    except Exception as e:
                        user_dict["metadata"] = {"error": str(e)}
                    
                    all_users.append(user_dict)
                
                # Filter by user type
                debug_info["azure_users"] = [u for u in all_users if u.get("user_type") == "azure"]
                debug_info["local_users"] = [u for u in all_users if u.get("user_type") == "local"]
                
                # Check login_users table schema
                cursor.execute("PRAGMA table_info(login_users)")
                debug_info["login_table_schema"] = [dict(row) for row in cursor.fetchall()]
                
                conn.close()
            except Exception as e:
                debug_info["db_error"] = str(e)
        
        # Get information from UserManager for comparison
        try:
            user_manager = UserManager()
            all_users = user_manager.get_all_users()
            debug_info["user_manager_data"] = all_users
        except Exception as e:
            debug_info["user_manager_error"] = str(e)
        
        # Return the debug info
        return 200, {"content-type": "application/json"}, {"debug_info": debug_info}
    except Exception as e:
        logger.error(f"Error in debug_azure_users: {str(e)}")
        return 500, {}, {"error": f"Server error: {str(e)}"} 