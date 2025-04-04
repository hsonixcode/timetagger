"""
Default script to run timetagger.

The timetagger library behaves like a framework; it provides the
building blocks to setup a timetracking app. This script puts things
together in the "default way". You can also create your own script to
customize/extend timetagger or embed in it a larger application.

A major hurdle in deploying an app like this is user authentication.
Timetagger implements its own token-based authentication, but it needs
to be "bootstrapped": the server needs to provide the first webtoken
when it has established trust in some way.

This script implements two methods to do this:
* A single-user login when client and server are on the same machine (localhost).
* Authentication with credentials specified as config params.

If you want another form of login, you will need to implement that yourself,
using a modified version of this script.
"""

import os
import sys
import json
import logging
import base64
from base64 import b64decode
from importlib import resources
import jinja2
import time
import asyncio
import iptools
import httpx
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Union

import asgineer
import itemdb
import pscript
import timetagger
from timetagger import config
from timetagger.server import (
    authenticate,
    AuthException,
    api_handler_triage,
    get_webtoken_unsafe,
    create_assets_from_dir,
    enable_service_worker,
)

# Import our multiuser API handlers - change from relative to absolute import
from timetagger.multiuser.api import get_users, search_users, update_user_access, get_login_users, backfill_login_database, debug_azure_users, update_user_role
# Import the api module properly for function calls
from timetagger.multiuser import api

# Import the check_admin_status_sync function
from timetagger.multiuser.auth_utils import check_admin_status_sync
from timetagger.server.config_api import get_full_app_config, update_app_config

# Import database initialization functions
from timetagger.server.db_utils import initialize_database, get_engine

# Import default_template and md2html from the server module
from timetagger.server._assets import default_template, md2html


# Helper function to extract auth info from request
async def get_auth_info(request):
    """Extract authentication information from the request.
    Returns a dict with authentication details.
    """
    auth_info = {}
    
    # Get authtoken from header
    authtoken = request.headers.get('authtoken', '')
    if authtoken:
        # Try to decode the token to get user information
        try:
            # Split the token into parts
            parts = authtoken.split('.')
            if len(parts) >= 2:
                # The payload is the second part
                payload = parts[1]
                # Ensure correct padding for base64 decoding
                payload += '=' * (-len(payload) % 4)
                # Decode the payload
                decoded = base64.urlsafe_b64decode(payload).decode('utf-8')
                token_data = json.loads(decoded)
                
                # Extract relevant user information
                auth_info['username'] = token_data.get('username', '')
                auth_info['is_admin'] = token_data.get('is_admin', False)
                auth_info['token'] = authtoken
                
                logging.info(f"Extracted auth info from token: username={auth_info['username']}, is_admin={auth_info['is_admin']}")
            else:
                logging.warning("Invalid token format: not enough parts")
        except Exception as e:
            logging.error(f"Error extracting auth info from token: {str(e)}")
    
    # If no username from token, try proxy auth
    if not auth_info.get('username') and config.proxy_auth_enabled:
        proxy_username = await get_username_from_proxy(request)
        if proxy_username:
            auth_info['username'] = proxy_username
            logging.info(f"Using username from proxy: {proxy_username}")
    
    return auth_info


# Special hooks exit early
if __name__ == "__main__" and len(sys.argv) >= 2:
    if sys.argv[1] in ("--version", "version"):
        print("timetagger", timetagger.__version__)
        print("asgineer", asgineer.__version__)
        print("itemdb", itemdb.__version__)
        print("pscript", pscript.__version__)
        sys.exit(0)


logger = logging.getLogger(__name__) # Use current module name for logger

# Get sets of assets provided by TimeTagger
common_assets = create_assets_from_dir("timetagger.common")
apponly_assets = create_assets_from_dir("timetagger.app")
image_assets = create_assets_from_dir("timetagger.images")
page_assets = create_assets_from_dir("timetagger.pages")

# Explicitly remove potentially problematic files if they exist
if "index.md" in page_assets:
    del page_assets["index.md"]
if "index.html" in page_assets:
    del page_assets["index.html"]
if "_template.html" in page_assets: # Ensure template from pages is not used directly
    del page_assets["_template.html"]
if "" in page_assets: # Ensure empty key (rendered index) is not present yet
     del page_assets[""]
if "configure_external_auth.html" in page_assets: # Remove pre-rendered version if it exists
     del page_assets["configure_external_auth.html"]


# Combine asset dictionaries
app_assets = dict(**common_assets, **image_assets, **apponly_assets)
# Render index.md from app_assets into the empty key ""
if "index.md" in app_assets:
    index_md_content = app_assets.pop("index.md") # Remove md source
    # Need the template from apponly_assets or default
    app_template_html = apponly_assets.get("_template.html", default_template)
    app_template = jinja2.Template(app_template_html)
    rendered_index_html = md2html(index_md_content, app_template)
    app_assets[""] = rendered_index_html # Add rendered HTML with empty key
    logger.info("Rendered app/index.md into app_assets['']")


web_assets = dict(**common_assets, **image_assets, **page_assets)
# Render configure_external_auth.md into web_assets["configure_external_auth"]
if "configure_external_auth.md" in web_assets:
     config_md_content = web_assets.pop("configure_external_auth.md") # Remove md source
     # Use the default template or one from page_assets if available
     page_template_html = page_assets.get("_template.html", default_template)
     page_template = jinja2.Template(page_template_html)
     rendered_config_html = md2html(config_md_content, page_template)
     web_assets["configure_external_auth"] = rendered_config_html # Add rendered HTML
     logger.info("Rendered pages/configure_external_auth.md into web_assets['configure_external_auth']")
else:
     logger.warning("configure_external_auth.md not found in page_assets")

# Log the keys of the collected assets AFTER processing
logger.info(f"Final app_asset keys: {list(app_assets.keys())}")
logger.info(f"Final web_asset keys: {list(web_assets.keys())}")

# Enable the service worker so the app can be used offline and is installable
enable_service_worker(app_assets)

# Turn asset dicts into handlers with proper caching
app_asset_handler = asgineer.utils.make_asset_handler(
    app_assets,
    max_age=3600  # 1 hour cache
)
web_asset_handler = asgineer.utils.make_asset_handler(
    web_assets,
    max_age=3600  # 1 hour cache
)


@asgineer.to_asgi
async def main_handler(request):
    """Main handler that serves the TimeTagger UI."""
    logger.info(f"Main handler received request for path (raw): {request.path}")
    path = request.path.strip("/")
    logger.info(f"Main handler processing stripped path: {path}")

    # Strip the timetagger prefix if present
    original_path_before_strip = path
    if path.startswith("timetagger/"):
        path = path[len("timetagger/"):]
        logger.info(f"Stripped 'timetagger/' prefix. New path: {path}")
    else:
         logger.info(f"Path '{original_path_before_strip}' did not start with 'timetagger/'")

    # Special handling for service worker
    if path == "sw.js":
        logger.info(f"Serving service worker: {path}")
        return await app_asset_handler(request, path)

    # Handle public API endpoints that don't require authentication
    if path == "api/v2/public_auth_config":
        from .server.config_api import get_public_auth_config
        try:
            auth_config = get_public_auth_config()
            return 200, {}, auth_config
        except Exception as e:
            logger.error("public_auth_config.handler_error",
                        error=str(e),
                        error_type=type(e).__name__)
            return 500, {"content-type": "application/json"}, {
                "error": "Internal server error",
                "details": str(e)
            }
            
    # Handle token exchange endpoint
    if path == "api/v2/token_exchange":
        if request.method.upper() != "POST":
            return 405, {"content-type": "application/json"}, {
                "error": "Method not allowed",
                "allowed_methods": ["POST"]
            }
        
        try:
            token_data = await request.get_json()
            logger.info(f"Token exchange request data: {token_data}")
            
            # Get Azure config from database with admin check bypassed
            from .server.config_api import get_full_app_config
            
            # Pass bypass_admin_check=True to avoid admin checks during auth
            mock_auth = {"username": "system"}  # Just for logging
            azure_config = get_full_app_config(mock_auth, bypass_admin_check=True)
            logger.info(f"Retrieved Azure config (excluding secret)")
            
            if not azure_config.get('azure_auth_enabled'):
                logger.error("Azure AD authentication is not enabled")
                return 403, {"content-type": "application/json"}, {
                    "error": "Azure AD authentication is not enabled"
                }
            
            # Validate required configuration
            required_fields = ['azure_client_id', 'azure_tenant_id', 'azure_client_secret', 'azure_instance']
            missing_fields = [field for field in required_fields if not azure_config.get(field)]
            if missing_fields:
                logger.error(f"Missing required Azure configuration: {missing_fields}")
                return 500, {"content-type": "application/json"}, {
                    "error": "Missing required Azure configuration",
                    "details": f"Missing fields: {', '.join(missing_fields)}"
                }
            
            # Prepare token request data
            token_request = {
                "client_id": azure_config['azure_client_id'],
                "client_secret": azure_config['azure_client_secret'],
                "code": token_data.get('code'),
                "redirect_uri": azure_config['azure_redirect_uri'],
                "grant_type": "authorization_code",
                "scope": "openid profile email offline_access"
            }
            
            # Log request details (excluding secret)
            safe_log_data = token_request.copy()
            safe_log_data['client_secret'] = '***'
            logger.info(f"Token request data (safe): {safe_log_data}")
            logger.info(f"Token request URL: {azure_config['azure_instance']}/{azure_config['azure_tenant_id']}/oauth2/v2.0/token")
            
            # Exchange code for tokens
            async with httpx.AsyncClient() as client:
                token_url = f"{azure_config['azure_instance']}/{azure_config['azure_tenant_id']}/oauth2/v2.0/token"
                
                try:
                    response = await client.post(
                        token_url,
                        data=token_request,
                        headers={"Content-Type": "application/x-www-form-urlencoded"}
                    )
                    
                    # Log response details for debugging
                    logger.info(f"Token exchange response status: {response.status_code}")
                    logger.info(f"Token exchange response headers: {dict(response.headers)}")
                    response_text = response.text
                    logger.info(f"Token exchange response body: {response_text[:200]}")  # Log first 200 chars
                    
                    if response.status_code != 200:
                        error_details = response_text
                        try:
                            error_json = response.json()
                            if 'error_description' in error_json:
                                error_details = error_json['error_description']
                            elif 'error' in error_json:
                                error_details = error_json['error']
                        except:
                            pass
                        
                        logger.error(f"Token exchange failed with status {response.status_code}: {error_details}")
                        return response.status_code, {"content-type": "application/json"}, {
                            "error": "Token exchange failed",
                            "details": error_details
                        }
                    
                    try:
                        tokens = response.json()
                        logger.info("Successfully parsed token response")
                        return 200, {"content-type": "application/json"}, tokens
                    except Exception as e:
                        logger.error(f"Failed to parse token response as JSON: {str(e)}")
                        return 500, {"content-type": "application/json"}, {
                            "error": "Token exchange failed",
                            "details": f"Failed to parse response as JSON: {str(e)}"
                        }
                        
                except httpx.RequestError as e:
                    logger.error(f"Request to Azure AD failed: {str(e)}")
                    return 500, {"content-type": "application/json"}, {
                        "error": "Token exchange failed",
                        "details": f"Request to Azure AD failed: {str(e)}"
                    }
                
        except Exception as e:
            logger.error(f"Token exchange error: {str(e)}")
            return 500, {"content-type": "application/json"}, {
                "error": "Token exchange failed",
                "details": str(e)
            }
            
    # Handle bootstrap authentication endpoint
    if path == "api/v2/bootstrap_authentication":
        return await get_webtoken(request)

    # Redirect root and home to app
    if not path or path == "home":
        logger.info(f"Redirecting root or home path: {path} to /timetagger/app/")
        return 307, {"Location": "/timetagger/app/"}, "Redirecting to app..."

    # Handle app path and app assets
    if path == "app" or path == "app/":
        logger.info(f"Serving pre-rendered index page (from index.md) for path: {path}")
        index_page_content = app_assets.get("") # Get the rendered index page
        if index_page_content is not None:
            # Inject current Azure AD config from localStorage into the template context
            # NOTE: This is a simplified approach. Ideally, the server fetches/validates this.
            # We pass placeholders here; the actual values are loaded by JS on the page.
            template_context = {
                 'timetagger_azure_client_id': '', # Placeholder
                 'timetagger_azure_tenant_id': '', # Placeholder
                 'timetagger_azure_redirect_uri': '', # Placeholder
                 'timetagger_azure_client_secret': '' # Placeholder
            }
            # Re-render the template with context (if needed by template, maybe not)
            # For now, just return the pre-rendered content.
            # A more advanced version might re-parse and inject context serverside.
            return 200, {"Content-Type": "text/html; charset=utf-8"}, index_page_content
        else:
             logger.error("Could not find the pre-rendered index page ('') in app_assets!")
             return 404, {}, "Error: Application index page not found."
    elif path.startswith("app/"):
        asset_path = path[4:]  # Remove 'app/' prefix
        logger.info(f"Serving app asset for path: {path}, asset requested: {asset_path}")
        
        # First try the exact path
        if asset_path in app_assets:
            return await app_asset_handler(request, asset_path)
            
        # If not found and it's a .js file, try looking for just the filename
        if '/' in asset_path and asset_path.endswith('.js'):
            filename = asset_path.split('/')[-1]
            if filename in app_assets:
                logger.info(f"Found JavaScript file by filename: {filename}")
                return await app_asset_handler(request, filename)
        
        logger.error(f"Asset not found: {asset_path}")
        return 404, {}, f"Asset not found: {asset_path}"

    # Handle API requests
    if path.startswith("api/v2/"):
        api_path = path[len("api/v2/"):]
        logger.info(f"Forwarding to API handler for path: {path}, API path: {api_path}")
        return await api_handler(request, api_path)

    # Handle configure_external_auth page
    if path == "configure_external_auth":
        logger.info(f"Serving configure_external_auth page")
        config_page_content = web_assets.get("configure_external_auth")
        if config_page_content is not None:
             # Similar to app index, pass placeholders; JS will load from localStorage
             template_context = {
                 'timetagger_azure_client_id': '', 
                 'timetagger_azure_tenant_id': '',
                 'timetagger_azure_redirect_uri': '',
                 'timetagger_azure_client_secret': '' 
             }
             # Return the pre-rendered config page HTML
             return 200, {"Content-Type": "text/html; charset=utf-8"}, config_page_content
        else:
             logger.error("Could not find the pre-rendered configure_external_auth page in web_assets!")
             return 404, {}, "Error: Configuration page not found."

    # Handle login, account pages (use web_asset_handler for generic pages now)
    if path in ["login", "account", "auth/callback"]:
        logger.info(f"Serving web asset handler for generic page path: {path}")
        # Let web_asset_handler serve the pre-rendered HTML from web_assets (e.g., web_assets['login'])
        page_key = path
        if path == "auth/callback": # Map callback to login page content
             page_key = "login"
             logger.info("Mapping 'auth/callback' to 'login' content.")
        return await web_asset_handler(request, page_key)

    # Handle all other paths with web assets (default fallback)
    logger.info(f"Serving web asset handler for path: {path}")
    return await web_asset_handler(request, path)


async def api_handler(request, path):
    """The default API handler. Designed to be short, so that
    the actual implementation can be changed easily.
    """
    
    # Skip bootstrap_authentication as it's handled by main_handler
    if path == "bootstrap_authentication":
        return 404, {}, "Not found: endpoint moved to /api/v2/bootstrap_authentication"
    
    # Handle public endpoints
    if path == "test_azure_config":
        from .server.config_api import test_azure_config
        
        if request.method.upper() != "POST":
            return 405, {"content-type": "application/json"}, {
                "error": "Method not allowed",
                "allowed_methods": ["POST"]
            }
        
        if not request.headers.get("content-type", "").startswith("application/json"):
            return 400, {"content-type": "application/json"}, {
                "error": "Invalid content type",
                "details": "Request must be application/json"
            }
        
        try:
            config_data = await request.get_json()
            result = await test_azure_config(config_data)
            return 200, {"content-type": "application/json"}, result
        except ValueError as e:
            return 400, {"content-type": "application/json"}, {
                "error": "Invalid configuration",
                "details": str(e)
            }
        except Exception as e:
            logger.error("test_azure_config.handler_error",
                        error=str(e),
                        error_type=type(e).__name__)
            return 500, {"content-type": "application/json"}, {
                "error": "Internal server error",
                "details": str(e)
            }
    
    # Handle public_auth_config endpoint
    if path == "public_auth_config":
        from .server.config_api import get_public_auth_config
        
        try:
            auth_config = get_public_auth_config()
            return 200, {"content-type": "application/json"}, auth_config
        except Exception as e:
            logger.error("public_auth_config.handler_error",
                        error=str(e),
                        error_type=type(e).__name__)
            return 500, {"content-type": "application/json"}, {
                "error": "Internal server error",
                "details": str(e)
            }
    
    # Authenticate and get user db for protected endpoints
    try:
        auth_info, db = await authenticate(request)
        
        # Include the token in auth_info to allow for token-based admin check
        token = request.headers.get("authtoken", "")
        if token and "token" not in auth_info:
            auth_info["token"] = token
            
        # Only validate if proxy auth is enabled
        if config.proxy_auth_enabled:
            await validate_auth(request, auth_info)
    except AuthException as err:
        logger.error(f"Authentication error: {err}")
        return 401, {}, f"unauthorized: {err}"

    # Extract query parameters from the URL and make them available
    # This ensures query parameters are properly passed to the API handlers
    if '?' in request.path:
        base_path, query_string = request.path.split('?', 1)
        # Store original path and querydict
        original_path = request.path
        original_querydict = request.querydict
        
        # Create query dict if it doesn't exist
        if not hasattr(request, 'querydict'):
            request.querydict = {}
        
        # Parse query parameters
        for param in query_string.split('&'):
            if '=' in param:
                key, value = param.split('=', 1)
                request.querydict[key] = value
            else:
                request.querydict[param] = ''
        
        # Log the parsed query parameters
        logger.info(f"Parsed query parameters: {request.querydict}")
    
    # Handle endpoints that require authentication
    return await api_handler_triage(request, path, auth_info, db)


async def api_handler_triage(request, path, auth_info, db):
    """
    Triage API endpoints to the appropriate handler.
    """
    # Extract important request info
    method = request.method
    path = path or request.path
    path = path.lstrip('/').rstrip('/')
    
    # Normalize path
    if path.startswith('api/'):
        path = path[4:]
    if path.startswith('v2/'):
        path = path[3:]
    
    logger.info(f"API triage for path: {path}")
    
    # Dispatch to appropriate handler
    if path == 'login':
        return await timetagger.server._apiserver.login(request)
    elif path == 'logout':
        return await timetagger.server._apiserver.logout(request)
    elif path == 'users':
        return await get_users(request, auth_info)
    elif path == 'login-users':
        return await get_login_users(request, auth_info)
    elif path == 'users/update-role':
        # Use the new update_user_role function
        from timetagger.multiuser.api import update_user_role
        return await update_user_role(request, auth_info)
    elif path == 'users/update-access':
        return await update_user_access(request, auth_info)
    elif path == 'users/debug-azure':
        return await debug_azure_users(request, auth_info)
    elif path == 'users/backfill':
        return await backfill_login_database(request, auth_info)
    elif path == 'azure/config':
        from timetagger.server.config_api import get_azure_config
        return await get_azure_config(request, auth_info)
    elif path == 'azure/config/update':
        from timetagger.server.config_api import update_azure_config
        return await update_azure_config(request, auth_info)
    elif path == 'app_config':
        if method == "GET":
            # Use the synchronous check_admin_status_sync function
            is_admin, source = check_admin_status_sync(auth_info)
            if not is_admin:
                logger.warning(f"Authentication error: Only admin users can access full configuration. Admin check source: {source}")
                return 403, {}, {"error": "Only admin users can access full configuration."}
            logger.info(f"Served app_config to admin user {auth_info.get('username')}. Admin check source: {source}")
            app_config = get_full_app_config(auth_info)
            return 200, {}, app_config
        elif method == "POST":
            try:
                import json
                # Read request body as bytes and parse as JSON
                body_bytes = await request.get_body()
                try:
                    body = json.loads(body_bytes.decode())
                except json.JSONDecodeError as e:
                    return 400, {}, f"Invalid JSON: {e}. Content: {body_bytes.decode()}"
                
                # Extract auth info directly
                auth_info = {}
                
                # Get authtoken from header
                authtoken = request.headers.get('authtoken', '')
                if authtoken:
                    # Try to decode the token to get user information
                    try:
                        # Split the token into parts
                        parts = authtoken.split('.')
                        if len(parts) >= 2:
                            # The payload is the second part
                            payload = parts[1]
                            # Ensure correct padding for base64 decoding
                            payload += '=' * (-len(payload) % 4)
                            # Decode the payload
                            decoded = base64.urlsafe_b64decode(payload).decode('utf-8')
                            token_data = json.loads(decoded)
                            
                            # Extract relevant user information
                            auth_info['username'] = token_data.get('username', '')
                            auth_info['is_admin'] = token_data.get('is_admin', False)
                            auth_info['token'] = authtoken
                            
                            logger.info(f"Extracted auth info from token: username={auth_info['username']}, is_admin={auth_info['is_admin']}")
                        else:
                            logger.warning("Invalid token format: not enough parts")
                    except Exception as e:
                        logger.error(f"Error extracting auth info from token: {str(e)}")
                
                # If no username from token, try proxy auth
                if not auth_info.get('username') and config.proxy_auth_enabled:
                    proxy_username = await get_username_from_proxy(request)
                    if proxy_username:
                        auth_info['username'] = proxy_username
                        logger.info(f"Using username from proxy: {proxy_username}")
                
                from timetagger.server.config_api import update_app_config
                
                try:
                    config = update_app_config(auth_info, body)
                    return 200, {}, json.dumps(config)
                except ValueError as e:
                    return 400, {}, f"Error updating app_config: {str(e)}"
                except AuthException as e:
                    return 403, {}, f"Authorization error: {str(e)}"
            except Exception as e:
                logger.error(f"Error in app_config endpoint: {str(e)}")
                return 500, {}, f"Internal server error: {str(e)}"
    # Data API endpoints
    elif path.startswith('data/'):
        # Strip 'data/' part
        subpath = path[5:]
        return await timetagger.server._apiserver.data_api_handler(request, subpath, auth_info, db)
    else:
        # Forward to the API server module for standard endpoints
        try:
            from timetagger.server._apiserver import api_handler_triage as _apiserver_triage
            logger.info(f"Forwarding to _apiserver.api_handler_triage for path: {path}")
            return await _apiserver_triage(request, path, auth_info, db)
        except Exception as e:
            logger.error(f"Error in API handler: {str(e)}")
            return 404, {}, {'error': f'API endpoint not found: {path}'}


async def get_webtoken(request):
    """Exhange some form of trust for a webtoken."""
    logger.info("get_webtoken called")
    
    try:
        body = await request.get_body()
        logger.info(f"Raw request body (first 100 bytes): {body[:100]}")
        decoded_body = b64decode(body)
        logger.info(f"Decoded body (first 100 bytes): {decoded_body[:100]}")
        auth_info = json.loads(decoded_body)
        logger.info(f"Auth info: {auth_info}")
    except Exception as e:
        logger.error(f"Error decoding request body: {str(e)}")
        return 400, {}, f"Bad request: {str(e)}"
    
    method = auth_info.get("method", "unspecified")
    logger.info(f"Auth method: {method}")

    # Enforce credential login if credentials are set
    if CREDENTIALS and method != "usernamepassword" and method != "azure":
        logger.warning(f"Credentials are set, but auth method was '{method}'. Forcing username/password or Azure AD.")
        return 401, {}, "Invalid authentication method. Use username/password or Azure AD."

    # Disable localhost login if credentials are set
    if CREDENTIALS and method == "localhost":
        logger.warning("Attempted localhost login, but credentials are set. Denying.")
        return 403, {}, "forbidden: localhost login disabled when credentials are set."

    if method == "localhost":
        return await get_webtoken_localhost(request, auth_info)
    elif method == "usernamepassword":
        return await get_webtoken_usernamepassword(request, auth_info)
    elif method == "proxy":
        return await get_webtoken_proxy(request, auth_info)
    elif method == "azure":
        return await get_webtoken_azure(request, auth_info)
    else:
        return 401, {}, f"Invalid authentication method: {method}"


async def get_webtoken_azure(request, auth_info):
    """An authentication handler that provides a webtoken when
    the user is authenticated through Azure AD.
    See `get_webtoken_unsafe()` for details.
    """
    logger.info("Starting get_webtoken_azure")
    logger.debug(f"[get_webtoken_azure] Received auth_info: {auth_info}")
    
    # Check if we have a username and access token (from client-side token exchange)
    username = auth_info.get("username", "").strip()
    access_token = auth_info.get("access_token", "").strip()
    id_token = auth_info.get("id_token", "").strip()
    
    if username and access_token:
        logger.info(f"[get_webtoken_azure] Using provided username from Azure AD: {username}")
        
        # Validate the ID token if provided
        if id_token:
            try:
                # Decode the token
                id_token_parts = id_token.split('.')
                # Ensure correct padding for base64 decoding
                payload_b64 = id_token_parts[1]
                payload_b64 += '=' * (-len(payload_b64) % 4) 
                id_token_payload = json.loads(base64.urlsafe_b64decode(payload_b64))
                
                # Make id_token_payload available to the surrounding scope for later use
                # Store in a variable at the wider scope
                token_payload = id_token_payload
                
                # Log the token payload for debugging
                logger.info(f"[get_webtoken_azure] ID token payload: {json.dumps(id_token_payload)[:500]}...")
                
                # Check token expiration but only log warnings
                exp = id_token_payload.get("exp", 0)
                current_time = int(time.time())
                if exp < current_time:
                    logger.warning(f"[get_webtoken_azure] ID token appears expired: exp={exp}, current={current_time}")
                    logger.warning(f"[get_webtoken_azure] Expiration date: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(exp))}")
                    logger.warning(f"[get_webtoken_azure] Current date: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(current_time))}")
                    logger.warning(f"[get_webtoken_azure] Continuing anyway for diagnostic purposes")
                else:
                    logger.info(f"[get_webtoken_azure] ID token expiration valid: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(exp))}")
                
                # Verify username matches but only log
                token_username = id_token_payload.get("preferred_username") or id_token_payload.get("email")
                if token_username and token_username.lower() != username.lower():
                    logger.warning(f"[get_webtoken_azure] Username mismatch in ID token: {token_username} vs {username}")
                    logger.warning(f"[get_webtoken_azure] Continuing anyway for diagnostic purposes")
                else:
                    logger.info(f"[get_webtoken_azure] ID token username matches: {token_username}")
                
                logger.info(f"[get_webtoken_azure] ID token validation completed")
            except Exception as e:
                logger.error(f"[get_webtoken_azure] ID token validation error: {str(e)}")
                logger.error(f"[get_webtoken_azure] Continuing anyway for diagnostic purposes")
        
        # Validate the access token by making a request to MS Graph API
        try:
            logger.info(f"[get_webtoken_azure] Validating access token...")
            async with httpx.AsyncClient() as client:
                # Instead of immediately failing, capture the response for inspection
                response = await client.get(
                    "https://graph.microsoft.com/v1.0/me",
                    headers={"Authorization": f"Bearer {access_token}"}
                )
                
                # Log the full response for debugging
                logger.info(f"[get_webtoken_azure] Microsoft Graph API response: Status={response.status_code}")
                logger.info(f"[get_webtoken_azure] Response headers: {dict(response.headers)}")
                logger.info(f"[get_webtoken_azure] Response body: {response.text[:200]}...")
                
                # Continue with the authentication process regardless of response status
                # We'll still log warnings but not block authentication
                if response.status_code != 200:
                    logger.warning(f"[get_webtoken_azure] Non-200 response from Microsoft Graph API: {response.status_code}")
                    logger.warning(f"[get_webtoken_azure] We're continuing anyway for diagnostic purposes")
                else:
                    # Get the user profile from the response if available
                    try:
                        profile = response.json()
                        token_username = profile.get("userPrincipalName") or profile.get("mail")
                        logger.info(f"[get_webtoken_azure] Profile username: {token_username}")
                        
                        # Log username comparison but don't block
                        if token_username and token_username.lower() != username.lower():
                            logger.warning(f"[get_webtoken_azure] Username mismatch: {token_username} vs {username}")
                        else:
                            logger.info(f"[get_webtoken_azure] Username match confirmed")
                    except Exception as e:
                        logger.warning(f"[get_webtoken_azure] Error parsing profile: {str(e)}")
            
            logger.info(f"[get_webtoken_azure] Token validation step completed")
        except Exception as e:
            # Log the error but continue the authentication flow
            logger.error(f"[get_webtoken_azure] Token validation error (continuing): {str(e)}")
            logger.error(f"[get_webtoken_azure] We're continuing anyway for diagnostic purposes")
        
        # First, check if the user is allowed to access the system
        try:
            from timetagger.multiuser.login_tracker import LoginTracker
            from timetagger.multiuser.user import UserManager
            
            # Check central login database first
            tracker = LoginTracker()
            email = username  # For Azure users, username is typically the email
            
            # Check if user exists and is allowed
            user_allowed = True  # Default to allowed
            
            # First check in the central login database
            user = tracker.get_login_by_email(email)
            if user:
                if user.get("access") == "not allowed":
                    logger.warning(f"[get_webtoken_azure] User {email} is not allowed to access the system (from central DB)")
                    return 403, {}, "Access denied: Your account has been disabled"
            
            # If not in central database, check UserManager
            else:
                user_manager = UserManager()
                all_users = user_manager.get_all_users_classified()
                
                # Find the user in the list
                matched_user = None
                for u in all_users:
                    if u.get("username") == username or u.get("email") == email:
                        matched_user = u
                        break
                
                if matched_user and not matched_user.get("is_allowed", True):
                    logger.warning(f"[get_webtoken_azure] User {email} is not allowed to access the system (from UserManager)")
                    return 403, {}, "Access denied: Your account has been disabled"
        
        except Exception as e:
            # Log error but continue - we'll default to allowing access
            logger.error(f"[get_webtoken_azure] Error checking user access: {e}")
        
        # Check if this is the first user (admin)
        is_admin = False
        
        # Check if user already exists in the database and their role
        try:
            from timetagger.multiuser.login_tracker import LoginTracker
            tracker = LoginTracker()
            existing_user = tracker.get_login_by_email(username)
            
            if existing_user and existing_user.get("role") == "admin":
                # If user exists and has admin role, set is_admin = True
                is_admin = True
                logger.info(f"[get_webtoken_azure] User {username} has admin role in database")
            elif CREDENTIALS:
                # If using credentials file, first user in credentials is admin
                is_admin = username == list(CREDENTIALS.keys())[0]
                logger.info(f"[get_webtoken_azure] Admin check based on credentials: {is_admin}")
            else:
                # If no credentials file, check if this is the first user in the database
                try:
                    from timetagger.server._apiserver import get_all_usernames
                    usernames = await get_all_usernames()
                    is_admin = not usernames or username == usernames[0]
                    logger.info(f"[get_webtoken_azure] Admin check based on database: {is_admin}")
                except Exception as e:
                    logger.error(f"[get_webtoken_azure] Error checking admin status: {e}")
                    is_admin = False
        except Exception as e:
            logger.error(f"[get_webtoken_azure] Error checking role from database: {e}")
            
            # Fall back to original checks
            if CREDENTIALS:
                # If using credentials file, first user in credentials is admin
                is_admin = username == list(CREDENTIALS.keys())[0]
                logger.info(f"[get_webtoken_azure] Admin check based on credentials: {is_admin}")
            else:
                # If no credentials file, check if this is the first user in the database
                try:
                    from timetagger.server._apiserver import get_all_usernames
                    usernames = await get_all_usernames()
                    is_admin = not usernames or username == usernames[0]
                    logger.info(f"[get_webtoken_azure] Admin check based on database: {is_admin}")
                except Exception as e:
                    logger.error(f"[get_webtoken_azure] Error checking admin status: {e}")
                    is_admin = False
        
        # Generate TimeTagger token with proper admin status
        token = await get_webtoken_unsafe(username, is_admin=is_admin)
        logger.info(f"Successfully generated TimeTagger token (admin: {is_admin})")
        print(f"[get_webtoken_azure] Generated token: {token[:10]}... (admin: {is_admin})")
        
        # Record the login in the central database
        try:
            from timetagger.multiuser.login_tracker import LoginTracker
            
            # Create login record
            email = username  # For Azure users, username is typically the email
            tracker = LoginTracker()
            
            # Check if user already exists first to preserve their role
            existing_user = tracker.get_login_by_email(email)
            
            # Prepare token metadata if available
            token_metadata = {}
            if 'token_payload' in locals():
                token_metadata = {k: v for k, v in token_payload.items() 
                                 if k in ["name", "given_name", "family_name"]}
            
            user_data = {
                "email": email,
                "username": username,
                "user_type": "azure",
                "is_allowed": True,  # Azure users are allowed by default
                "source_db": f"{username}.db",
                "metadata": {
                    "auth_method": "azure",
                    "auth_flow": "token",
                    "access_token_present": bool(access_token)
                }
            }
            
            # Add token metadata if available
            if token_metadata:
                user_data["metadata"]["token_payload"] = token_metadata
            
            # Handle role preservation differently
            # For existing users, always preserve their role
            if existing_user:
                # Preserve the existing role and is_allowed status
                existing_role = existing_user.get("role")
                if existing_role:
                    user_data["role"] = existing_role
                    logger.info(f"[get_webtoken_azure] Preserving existing role '{existing_role}' for user {email}")
                else:
                    # Default to admin if is_admin flag is set, otherwise user
                    user_data["role"] = "admin" if is_admin else "user"
                    logger.info(f"[get_webtoken_azure] Setting role to '{user_data['role']}' based on is_admin={is_admin}")
                
                # Check if there's existing allow/deny status we should preserve
                existing_access = existing_user.get("access")
                if existing_access == "not allowed":
                    user_data["is_allowed"] = False
                    logger.info(f"[get_webtoken_azure] Preserving existing access status 'not allowed' for user {email}")
            else:
                # New user - set based on is_admin flag
                user_data["role"] = "admin" if is_admin else "user"
                logger.info(f"[get_webtoken_azure] New user - setting role to '{user_data['role']}' based on is_admin={is_admin}")
            
            # Record login asynchronously (don't block the authentication flow)
            try:
                await tracker.record_login(user_data)
                logger.info(f"[get_webtoken_azure] Recorded login for user {email} in central database (code flow)")
            except Exception as login_err:
                logger.error(f"[get_webtoken_azure] Error recording login (code flow): {login_err}")
                # Continue authentication even if login recording fails
        
        except Exception as e:
            # Log error but continue authentication flow
            logger.error(f"[get_webtoken_azure] Error recording login (code flow): {e}")
        
        return 200, {}, dict(token=token)
    
    # If we don't have a username and access token, try the code flow (THIS PATH SHOULD NOT BE USED NORMALLY)
    # The client should handle the code exchange first via token_exchange_handler
    logger.warning("[get_webtoken_azure] Reached code exchange path - this is unexpected.")
    print("[get_webtoken_azure] Reached code exchange path - this is unexpected.")
    code = auth_info.get("code", "").strip()
    if not code:
        logger.error("No Azure AD code provided in auth_info")
        return 403, {}, "forbidden: no Azure AD code provided"

    # Exchange code for tokens (Duplicated logic - preferably handled by token_exchange_handler)
    logger.warning("[get_webtoken_azure] Performing code exchange (duplicated logic)...")
    azure_instance = os.environ.get("TIMETAGGER_AZURE_INSTANCE", "https://login.microsoftonline.com")
    azure_tenant_id = os.environ.get("TIMETAGGER_AZURE_TENANT_ID")
    azure_client_id = os.environ.get("TIMETAGGER_AZURE_CLIENT_ID")
    azure_client_secret = os.environ.get("TIMETAGGER_AZURE_CLIENT_SECRET")
    azure_redirect_uri = os.environ.get("TIMETAGGER_AZURE_REDIRECT_URI")
    
    token_url = f"{azure_instance}/{azure_tenant_id}/oauth2/v2.0/token"
    
    # Ensure correct scopes are requested
    scope = f"{azure_client_id}/.default openid profile email offline_access"
    
    token_data = {
        "client_id": azure_client_id,
        "client_secret": azure_client_secret,
        "code": code,
        "redirect_uri": azure_redirect_uri,
        "grant_type": "authorization_code",
        "scope": scope # Use corrected scope
    }

    logger.info(f"Token URL: {token_url}")
    logger.info(f"Final Token request scope: {scope}") # Log the final scope
    logger.info(f"Token request data: {token_data}")

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                token_url,
                data=token_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            response.raise_for_status()
            tokens = response.json()
            logger.info("Successfully received tokens from Azure AD")
    except Exception as e:
        logger.error(f"Azure AD token exchange failed: {str(e)}")
        if hasattr(e, 'response'):
            logger.error(f"Response status: {e.response.status_code}")
            logger.error(f"Response body: {e.response.text}")
        return 403, {}, f"forbidden: Azure AD token exchange failed: {str(e)}"

    # Get user info from ID token
    try:
        id_token_parts = tokens["id_token"].split('.')
        # Ensure correct padding for base64 decoding
        payload_b64 = id_token_parts[1]
        payload_b64 += '=' * (-len(payload_b64) % 4) 
        id_token_payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        
        # Validate the token expiration
        exp = id_token_payload.get("exp", 0)
        current_time = int(time.time())
        if exp < current_time:
            logger.error(f"[get_webtoken_azure] ID token expired: exp={exp}, current={current_time}")
            return 401, {}, "Unauthorized: Azure AD token expired"
            
        # Check for required claims
        required_claims = ["aud", "iss", "sub"]
        missing_claims = [claim for claim in required_claims if claim not in id_token_payload]
        if missing_claims:
            logger.error(f"[get_webtoken_azure] ID token missing required claims: {missing_claims}")
            return 401, {}, "Unauthorized: Invalid ID token (missing claims)"
        
        # Verify audience matches our client ID
        if id_token_payload.get("aud") != azure_client_id:
            logger.error(f"[get_webtoken_azure] ID token audience mismatch: {id_token_payload.get('aud')} vs {azure_client_id}")
            return 401, {}, "Unauthorized: Invalid token audience"
        
        username = id_token_payload.get("preferred_username") or id_token_payload.get("email")
        if not username:
            logger.error("No username or email found in ID token")
            return 403, {}, "forbidden: No username or email found in ID token"
        logger.info(f"Successfully extracted username: {username}")
    except Exception as e:
        logger.error(f"Failed to extract user info from token: {str(e)}")
        return 403, {}, f"forbidden: Failed to extract user info from token: {str(e)}"

    # Return the webtoken for Azure AD user - Set is_admin to False
    is_admin = False
    
    # Check if user already exists in the database and check their role
    try:
        from timetagger.multiuser.login_tracker import LoginTracker
        tracker = LoginTracker()
        existing_user = tracker.get_login_by_email(username)
        
        if existing_user and existing_user.get("role") == "admin":
            # If user exists and has admin role, set is_admin = True
            is_admin = True
            logger.info(f"[get_webtoken_azure] Code flow: User {username} has admin role in database")
    except Exception as e:
        logger.error(f"[get_webtoken_azure] Code flow: Error checking role from database: {e}")
        
    token = await get_webtoken_unsafe(username, is_admin=is_admin)
    logger.info(f"Successfully generated TimeTagger token (via code flow, admin: {is_admin})")
    print(f"[get_webtoken_azure] Generated token (via code flow): {token[:10]}... (admin: {is_admin})")
    
    # Record the login in the central database
    try:
        from timetagger.multiuser.login_tracker import LoginTracker
        
        # Create login record
        email = username  # For Azure users, username is typically the email
        tracker = LoginTracker()
        
        # Check if user already exists first to preserve their role
        existing_user = tracker.get_login_by_email(email)
        
        # Prepare token metadata if available
        token_metadata = {}
        if 'token_payload' in locals():
            token_metadata = {k: v for k, v in token_payload.items() 
                             if k in ["name", "given_name", "family_name"]}
        
        user_data = {
            "email": email,
            "username": username,
            "user_type": "azure",
            "is_allowed": True,  # Azure users are allowed by default
            "source_db": f"{username}.db",
            "metadata": {
                "auth_method": "azure",
                "auth_flow": "token",
                "access_token_present": bool(access_token)
            }
        }
        
        # Add token metadata if available
        if token_metadata:
            user_data["metadata"]["token_payload"] = token_metadata
        
        # Handle role preservation differently
        # For existing users, always preserve their role
        if existing_user:
            # Preserve the existing role and is_allowed status
            existing_role = existing_user.get("role")
            if existing_role:
                user_data["role"] = existing_role
                logger.info(f"[get_webtoken_azure] Preserving existing role '{existing_role}' for user {email}")
            else:
                # Default to admin if is_admin flag is set, otherwise user
                user_data["role"] = "admin" if is_admin else "user"
                logger.info(f"[get_webtoken_azure] Setting role to '{user_data['role']}' based on is_admin={is_admin}")
            
            # Check if there's existing allow/deny status we should preserve
            existing_access = existing_user.get("access")
            if existing_access == "not allowed":
                user_data["is_allowed"] = False
                logger.info(f"[get_webtoken_azure] Preserving existing access status 'not allowed' for user {email}")
        else:
            # New user - set based on is_admin flag
            user_data["role"] = "admin" if is_admin else "user"
            logger.info(f"[get_webtoken_azure] New user - setting role to '{user_data['role']}' based on is_admin={is_admin}")
        
        # Record login asynchronously (don't block the authentication flow)
        try:
            await tracker.record_login(user_data)
            logger.info(f"[get_webtoken_azure] Recorded login for user {email} in central database (code flow)")
        except Exception as login_err:
            logger.error(f"[get_webtoken_azure] Error recording login (code flow): {login_err}")
            # Continue authentication even if login recording fails
    except Exception as e:
        # Log error but continue authentication flow
        logger.error(f"[get_webtoken_azure] Error recording login (code flow): {e}")
    
    return 200, {}, dict(token=token)


async def get_webtoken_proxy(request, auth_info):
    """An authentication handler that provides a webtoken when
    the user is autheticated through a trusted reverse proxy
    by a given header. See `get_webtoken_unsafe()` for details.
    """

    # Check if proxy auth is enabled
    if not config.proxy_auth_enabled:
        return 403, {}, "forbidden: proxy auth is not enabled"

    # Check if the request comes from a trusted proxy
    client = request.scope["client"][0]
    if client not in TRUSTED_PROXIES:
        return 403, {}, "forbidden: the proxy is not trusted"

    # Get username from request header
    user = await get_username_from_proxy(request)
    if not user:
        return 403, {}, "forbidden: no proxy user provided"

    # Return the webtoken for proxy user
    token = await get_webtoken_unsafe(user)
    return 200, {}, dict(token=token)


async def get_webtoken_usernamepassword(request, auth_info):
    """An authentication handler that provides a webtoken when the
    user provides the correct username and password as listed in
    the server config (`config.credentials`). See `get_webtoken_unsafe()` for details.
    """
    logger.info("Starting get_webtoken_usernamepassword")
    # Get username and password from request body
    username = auth_info.get("username", "").strip()
    password = auth_info.get("password", "").strip()
    if not (username and password):
        logger.warning("Username or password missing in request")
        return 400, {}, "bad request: username or password missing"
    # Get stored password from config
    stored_password = CREDENTIALS.get(username, "")
    if not stored_password:
        logger.warning(f"Username '{username}' not found in credentials")
        return 403, {}, "forbidden: invalid credentials"
    # Check the password (plain text comparison)
    if password != stored_password:
        logger.warning(f"Password check failed for user '{username}'")
        return 403, {}, "forbidden: invalid credentials"
    
    # Check if user is allowed to access the system (for regular users, not the admin)
    # Admin users from credentials file are always allowed
    if not username == list(CREDENTIALS.keys())[0]:  # Skip check for first user (admin)
        try:
            from timetagger.multiuser.login_tracker import LoginTracker
            from timetagger.multiuser.user import UserManager
            
            # First check in the central login database
            tracker = LoginTracker()
            
            # Try to find user by username as email
            user = tracker.get_login_by_email(username)
            
            # If not found, try to create a local-style email
            if not user and '@' not in username:
                local_email = f"{username}@localhost"
                user = tracker.get_login_by_email(local_email)
            
            if user:
                if user.get("access") == "not allowed":
                    logger.warning(f"[get_webtoken_usernamepassword] User {username} is not allowed to access the system (from central DB)")
                    return 403, {}, "Access denied: Your account has been disabled"
            
            # If not in central database, check UserManager
            else:
                user_manager = UserManager()
                all_users = user_manager.get_all_users_classified()
                
                # Find the user in the list
                matched_user = None
                for u in all_users:
                    if u.get("username") == username:
                        matched_user = u
                        break
                
                if matched_user and not matched_user.get("is_allowed", True):
                    logger.warning(f"[get_webtoken_usernamepassword] User {username} is not allowed to access the system (from UserManager)")
                    return 403, {}, "Access denied: Your account has been disabled"
        
        except Exception as e:
            # Log error but continue - we'll default to allowing access
            logger.error(f"[get_webtoken_usernamepassword] Error checking user access: {e}")
    
    # Return the webtoken
    logger.info(f"Credentials validated successfully for user '{username}'")
    token = await get_webtoken_unsafe(username)
    logger.info(f"Generated token for user '{username}': {token[:10]}...")
    
    # Record the login in the central database
    try:
        from timetagger.multiuser.login_tracker import LoginTracker
        
        # Create login record - try to extract email from username
        email = username
        if '@' not in username:
            email = f"{username}@localhost"  # Fallback for local users without email
        
        tracker = LoginTracker()
        user_data = {
            "email": email,
            "username": username,
            "role": "user",  # Will be updated to admin if first user
            "user_type": "local",
            "is_allowed": True,  # Local users are allowed by default
            "source_db": f"{username}.db",
            "metadata": {
                "auth_method": "usernamepassword"
            }
        }
        
        # Check if this is the admin (first user in credentials)
        if CREDENTIALS and username == list(CREDENTIALS.keys())[0]:
            user_data["role"] = "admin"
        
        # Record login asynchronously (don't block the authentication flow)
        await tracker.record_login(user_data)
        logger.info(f"Recorded login for user {email} in central database")
    except Exception as e:
        # Log error but continue authentication flow
        logger.error(f"Error recording login: {e}")
    
    return 200, {}, dict(token=token)


async def get_webtoken_localhost(request, auth_info):
    """An authentication handler that provides a webtoken when the
    hostname is localhost. See `get_webtoken_unsafe()` for details.
    THIS IS DISABLED IF CREDENTIALS ARE SET.
    """
    # Explicitly disable if CREDENTIALS are set
    if CREDENTIALS:
        logger.warning("Attempted localhost login, but credentials are set. Denying.")
        return 403, {}, "forbidden: localhost login disabled when credentials are set."
        
    if not config.bind.startswith("127.0.0.1"):
        return (
            403,
            {},
            "Can only login via localhost if the server address (config.bind) is '127.0.0.1'",
        )
    # Don't allow localhost validation when proxy auth is enabled
    if config.proxy_auth_enabled:
        return 403, {}, "forbidden: disabled when proxy auth is available"
    # Establish that we can trust the client
    if request.host not in ("localhost", "127.0.0.1"):
        return 403, {}, "forbidden: must be on localhost"
    # Return the webtoken for the default user
    token = await get_webtoken_unsafe("defaultuser")
    return 200, {}, dict(token=token)


async def validate_auth(request, auth_info):
    """Validates that the autheticated user is still the same that
    is provided by the reverse proxy.
    """

    # Check that the proxy user is the same
    proxy_user = await get_username_from_proxy(request)
    if proxy_user and proxy_user != auth_info["username"]:
        raise AuthException("Autheticated user does not match proxy user")


def load_credentials():
    """Load credentials from config.credentials.
    The format is 'username:password' with multiple entries separated by commas or semicolons.
    Passwords are stored in plain text.
    """
    d = {}
    for s in config.credentials.replace(";", ",").split(","):
        name, _, password = s.partition(":")
        if name and password:  # Only add if both username and password are present
            d[name] = password
    return d


def load_trusted_proxies():
    ips = [s.strip() for s in config.proxy_auth_trusted.replace(";", ",").split(",")]
    return iptools.IpRangeList(*ips)


CREDENTIALS = load_credentials()
TRUSTED_PROXIES = load_trusted_proxies()


# Add the token exchange handler
async def token_exchange_handler(request):
    """Handle exchanging an authorization code for tokens with Azure AD."""
    try:
        logger.info("========== TOKEN EXCHANGE HANDLER CALLED ==========")
        logger.info("Token exchange handler called")
        
        # Get request body
        body_str = await request.get_body()
        logger.info(f"Request body: {body_str}")
        
        body = json.loads(body_str)
        logger.info(f"Parsed body: {body}")
        
        code = body.get("code")
        if not code:
            logger.error("No authorization code provided in request")
            return 400, {}, "Bad request: No authorization code provided"
        
        logger.info(f"Exchanging authorization code (first 10 chars): {code[:10]}...")
        
        # Check if we need to load configuration from database
        # If environment variables are not set, try loading from database
        azure_instance = os.environ.get("TIMETAGGER_AZURE_INSTANCE")
        azure_tenant_id = os.environ.get("TIMETAGGER_AZURE_TENANT_ID")
        azure_client_id = os.environ.get("TIMETAGGER_AZURE_CLIENT_ID")
        azure_client_secret = os.environ.get("TIMETAGGER_AZURE_CLIENT_SECRET")
        azure_redirect_uri = os.environ.get("TIMETAGGER_AZURE_REDIRECT_URI")
        
        # If any required config is missing from environment, load from database
        if not all([azure_tenant_id, azure_client_id, azure_client_secret]):
            logger.info("Some Azure configuration missing from environment, loading from database")
            try:
                from timetagger.server.config_api import get_full_app_config
                # Use bypass_admin_check during auth flow
                mock_auth = {"username": "system"}  # Just for logging
                config = get_full_app_config(mock_auth, bypass_admin_check=True)
                
                # Override environment variables with database config
                azure_instance = config.get("azure_instance", "https://login.microsoftonline.com")
                azure_tenant_id = config.get("azure_tenant_id")
                azure_client_id = config.get("azure_client_id")
                azure_client_secret = config.get("azure_client_secret")
                azure_redirect_uri = config.get("azure_redirect_uri")
                
                logger.info("Successfully loaded Azure configuration from database")
            except Exception as e:
                logger.error(f"Error loading Azure configuration from database: {e}")
                # Continue with environment variables if available
        
        # If still missing required config, return error
        if not azure_tenant_id or not azure_client_id or not azure_client_secret:
            logger.error(f"Missing required Azure AD configuration: tenant_id={azure_tenant_id}, client_id={azure_client_id}")
            return 500, {"content-type": "application/json"}, {"error": "Missing required Azure AD configuration"}
        
        token_url = f"{azure_instance}/{azure_tenant_id}/oauth2/v2.0/token"
        
        # Prepare token request data from the client request
        # Ensure correct scopes are requested for ID and refresh tokens
        requested_scope = body.get("scope", f"{azure_client_id}/.default openid profile email offline_access")
        required_scopes = ["openid", "profile", "email", "offline_access"]
        final_scope_parts = set(requested_scope.split())
        for s in required_scopes:
            final_scope_parts.add(s)
        final_scope = " ".join(sorted(list(final_scope_parts)))
        
        token_data = {
            "client_id": azure_client_id,
            "client_secret": azure_client_secret,
            "code": code,
            "redirect_uri": body.get("redirect_uri", azure_redirect_uri),
            "grant_type": "authorization_code",
            "scope": final_scope # Use the corrected scope
        }
        
        logger.info(f"Token URL: {token_url}")
        logger.info(f"Final Token request scope: {final_scope}") # Log the final scope
        logger.info(f"Token request data: {token_data}")
        
        # Make the token request
        try:
            async with httpx.AsyncClient() as client:
                # Using httpx to handle form encoding properly
                response = await client.post(
                    token_url,
                    data=token_data,  # httpx will properly format this as application/x-www-form-urlencoded
                    headers={"Content-Type": "application/x-www-form-urlencoded"}
                )
                response.raise_for_status()
                tokens = response.json()
                logger.info("Successfully received tokens from Azure AD")
                
                # Return tokens to the client
                return 200, {"content-type": "application/json"}, tokens
        except Exception as e:
            logger.error(f"Azure AD token exchange failed: {str(e)}")
            if hasattr(e, 'response'):
                logger.error(f"Response status: {e.response.status_code}")
                logger.error(f"Response body: {e.response.text}")
            return 500, {"content-type": "application/json"}, {"error": f"Azure AD token exchange failed: {str(e)}"}
    except Exception as e:
        logger.error(f"Error in token_exchange_handler: {str(e)}")
        return 500, {"content-type": "application/json"}, {"error": f"Internal server error: {str(e)}"}


async def pages_handler(request, path, template_context):
    """Handle markdown page rendering with template context."""
    try:
        from timetagger.server._assets import md2html
        from importlib import resources
        
        # Read the markdown file
        md_content = resources.files("timetagger.pages").joinpath(f"{path}.md").read_text()
        
        # Render with template context
        html_content = md2html(md_content, template_context)
        
        return 200, {"content-type": "text/html"}, html_content
    except Exception as e:
        logger.error(f"Error rendering template: {e}")
        return 500, {}, f"Error rendering template: {e}"


# Define the get_username_from_proxy function
async def get_username_from_proxy(request):
    """Extract username from a proxy header."""
    if not config.proxy_auth_enabled:
        return None
    
    header_name = config.proxy_auth_header
    if not header_name:
        return None
    
    # Get the header value
    username = request.headers.get(header_name, "")
    if not username:
        logger.warning(f"Proxy auth header '{header_name}' is empty")
        return None
    
    logger.info(f"Extracted username '{username}' from proxy header '{header_name}'")
    return username.strip()


if __name__ == "__main__":
    # Initialize the database before starting the server
    try:
        logger.info("Initializing database...")
        initialize_database()
        logger.info("Database initialization complete")
    except Exception as e:
        logger.error(f"Error initializing database: {str(e)}")
        logger.info("Continuing startup despite database initialization error")
    
    # Start the server
    asgineer.run(
        "timetagger.__main__:main_handler", "uvicorn", config.bind, log_level="debug"
    )
