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
from .auth_utils import check_admin_status, invalidate_user_token, check_admin_status_sync

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
    API endpoint handler to update a user's access status and role.
    
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
        role = body.get("role")  # Optional role parameter
        
        if not username:
            return 400, {}, {"error": "Username is required"}
        
        if is_allowed is None:
            return 400, {}, {"error": "is_allowed is required"}
        
        # Validate role if provided
        valid_roles = ["user", "admin"]
        if role and role not in valid_roles:
            return 400, {}, {"error": f"Invalid role. Must be one of: {', '.join(valid_roles)}"}
        
        # Update user access in the UserManager
        user_manager = UserManager()
        result = await user_manager.update_user_access(username, is_allowed, role)
        
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
                # User exists in login database, update access status and role
                user_data = {
                    "email": email,
                    "username": username,
                    "role": role or user.get("role", "user"),  # Use provided role or keep existing
                    "user_type": user.get("user_type", "local"),
                    "is_allowed": is_allowed,
                    "source_db": user.get("source_db", f"{username}.db"),
                    "metadata": user.get("metadata", {})
                }
                
                # Record the update
                await login_tracker.record_login(user_data)
                logger.info(f"Updated user in central login database: {email} (role: {user_data['role']}, access: {is_allowed})")
        except Exception as e:
            # Log error but continue (this is not critical)
            logger.error(f"Error updating user in central login database: {str(e)}")
        
        # Return success message
        response_message = f"User '{username}' updated successfully"
        if role:
            response_message += f" (role: {role}, access: {is_allowed})"
        else:
            response_message += f" (access: {is_allowed})"
        
        return 200, {"content-type": "application/json"}, {
            "success": True,
            "message": response_message
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

async def debug_azure_users(request, auth_info) -> Tuple[int, Dict[str, str], Dict[str, Any]]:
    """
    API endpoint for debugging Azure users.
    This is mainly for development and troubleshooting.
    
    Args:
        request: The HTTP request object
        auth_info: The authentication info dictionary
        
    Returns:
        tuple: (status_code, headers, response_body)
    """
    # Check if user is authenticated and has admin privileges
    if not auth_info:
        return 401, {}, {"error": "Authentication required"}
    
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
        import os
        from timetagger.server._utils import ROOT_USER_DIR
        from timetagger.server.db_utils import get_session, Record, Settings, UserInfo
        from sqlalchemy import func, distinct
        
        debug_info = {
            "request_info": request_info,
            "user_dirs": [],
            "db_files": []
        }
        
        # Scan user directories (for legacy support)
        user_path = Path(ROOT_USER_DIR)
        if user_path.exists():
            debug_info["user_dirs"] = [str(d) for d in user_path.iterdir() if d.is_dir()]
            
            # Look for db files
            db_files = list(user_path.glob("*.db")) + list(user_path.glob("**/*.db"))
            debug_info["db_files"] = [str(f) for f in db_files]
        
        # Query the database directly
        try:
            session = get_session()
            
            # Get all azure users from settings
            azure_users = []
            local_users = []
            
            # Query all distinct usernames
            usernames = session.query(distinct(Settings.username)).all()
            usernames = [u[0] for u in usernames]
            
            for username in usernames:
                # Check if user is Azure user
                azure_info_setting = session.query(Settings).filter_by(
                    username=username,
                    key="azure_info"
                ).first()
                
                auth_info_setting = session.query(Settings).filter_by(
                    username=username,
                    key="auth_info"
                ).first()
                
                user_info_setting = session.query(Settings).filter_by(
                    username=username,
                    key="user_info"
                ).first()
                
                # Determine if Azure user
                is_azure = False
                user_data = {"username": username}
                
                # Check azure_info
                if azure_info_setting:
                    azure_info = getattr(azure_info_setting, "value", {}) or {}
                    is_azure = True
                    user_data.update({
                        "email": azure_info.get("email", username),
                        "display_name": azure_info.get("display_name", username),
                        "role": azure_info.get("role", "user"),
                        "source": "azure_info"
                    })
                
                # Check auth_info
                elif auth_info_setting:
                    auth_info = getattr(auth_info_setting, "value", {}) or {}
                    if auth_info.get("auth_type") == "azure":
                        is_azure = True
                        user_data.update({
                            "email": auth_info.get("email", username),
                            "display_name": auth_info.get("name", username),
                            "role": auth_info.get("role", "user"),
                            "source": "auth_info"
                        })
                
                # Check user_info
                elif user_info_setting:
                    user_info = getattr(user_info_setting, "value", {}) or {}
                    if user_info.get("auth_type") == "azure" or user_info.get("user_type") == "azure":
                        is_azure = True
                        user_data.update({
                            "email": user_info.get("email", username),
                            "display_name": user_info.get("display_name", username),
                            "role": user_info.get("role", "user"),
                            "source": "user_info"
                        })
                
                # Add to appropriate list
                if is_azure:
                    azure_users.append(user_data)
                else:
                    if not user_data.get("source"):
                        user_data["source"] = "default"
                    local_users.append(user_data)
                    
            debug_info["azure_users"] = azure_users
            debug_info["local_users"] = local_users
            
            # Get table statistics
            debug_info["database_stats"] = {
                "records_count": session.query(func.count(Record.key)).scalar(),
                "settings_count": session.query(func.count(Settings.key)).scalar(),
                "userinfo_count": session.query(func.count(UserInfo.key)).scalar(),
                "unique_users": session.query(func.count(distinct(Settings.username))).scalar()
            }
            
            session.close()
            
        except Exception as e:
            debug_info["db_error"] = str(e)
        
        # Get information from UserManager for comparison
        try:
            user_manager = UserManager()
            all_users = user_manager.get_all_users()
            debug_info["user_manager_data"] = all_users
        except Exception as e:
            debug_info["user_manager_error"] = str(e)
        
        # Get information from LoginTracker
        try:
            from .login_tracker import LoginTracker
            tracker = LoginTracker()
            login_stats = tracker.get_login_stats()
            debug_info["login_tracker_stats"] = login_stats
        except Exception as e:
            debug_info["login_tracker_error"] = str(e)
        
        # Return the debug info
        return 200, {"content-type": "application/json"}, {"debug_info": debug_info}
    except Exception as e:
        logger.error(f"Error in debug_azure_users: {str(e)}")
        return 500, {}, {"error": f"Server error: {str(e)}"}

async def update_user_role(request, auth_info):
    """Update a user's role in the login database.
    
    Args:
        request: The HTTP request object
        auth_info: The authentication info dictionary
        
    Returns:
        tuple: (status_code, headers, response_body)
    """
    # Check if user is admin using the standardized check
    is_admin, source = check_admin_status_sync(auth_info)
    if not is_admin:
        logger.warning(f"Non-admin user {auth_info.get('username')} attempted to update user role. Admin check source: {source}")
        return 403, {}, {"error": "Only admin users can update user roles."}
    
    # Parse request body
    try:
        body = await request.json()
    except json.JSONDecodeError:
        return 400, {}, {"error": "Invalid JSON in request body"}
    
    # Validate required fields
    username = body.get("username")
    role = body.get("role")
    
    if not username:
        return 400, {}, {"error": "Username is required"}
    
    if not role:
        return 400, {}, {"error": "Role is required"}
    
    if role not in ["admin", "user"]:
        return 400, {}, {"error": "Role must be either 'admin' or 'user'"}
    
    # Update the user role in the login database
    from .login_tracker import LoginTracker
    tracker = LoginTracker()
    
    # Use the update_user_role method
    success, message = await tracker.update_user_role(username, role)
    
    if not success:
        logger.warning(f"Failed to update role: {message}")
        return 404, {}, {"error": message}
    
    # If we're updating our own role, invalidate our token to reflect the change
    if username == auth_info.get("username"):
        invalidate_user_token(username)
    
    logger.info(f"User {username} role updated to {role} by admin {auth_info.get('username')}")
    return 200, {}, {"success": True, "username": username, "role": role, "message": message} 