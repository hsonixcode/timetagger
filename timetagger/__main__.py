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

import bcrypt
import asgineer
import itemdb
import pscript
import iptools
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
import httpx


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
            config = get_public_auth_config()
            return 200, {}, config
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
            
            # Get Azure config from database (use full config to get client secret)
            from .server.config_api import get_full_app_config
            # Create a mock admin auth_info to access full config
            mock_admin_auth = {"is_admin": True}
            azure_config = get_full_app_config(mock_admin_auth)
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
    
    # Authenticate and get user db for protected endpoints
    try:
        auth_info, db = await authenticate(request)
        # Only validate if proxy auth is enabled
        if config.proxy_auth_enabled:
            await validate_auth(request, auth_info)
    except AuthException as err:
        print(f"Authentication error: {err}")
        logger.error(f"Authentication error: {err}")
        return 401, {}, f"unauthorized: {err}"

    # Handle endpoints that require authentication
    return await api_handler_triage(request, path, auth_info, db)


async def api_handler_triage(request, path, auth_info, db):
    """Handle API requests that require authentication."""
    
    # Get the request method
    method = request.method.upper()
    
    # Handle Azure config endpoints
    if path == "config/azure":
        from .server.config_api import get_azure_config, update_azure_config
        try:
            if method == "GET":
                config = get_azure_config(auth_info)
                return 200, {"content-type": "application/json"}, config
            elif method == "POST":
                if not request.headers.get("content-type", "").startswith("application/json"):
                    return 400, {"content-type": "application/json"}, {
                        "error": "Invalid content type",
                        "details": "Request must be application/json"
                    }
                try:
                    new_config = await request.get_json()
                    updated_config = update_azure_config(auth_info, new_config)
                    return 200, {"content-type": "application/json"}, updated_config
                except ValueError as e:
                    return 400, {"content-type": "application/json"}, {
                        "error": "Invalid configuration",
                        "details": str(e)
                    }
            else:
                return 405, {"content-type": "application/json"}, {
                    "error": "Method not allowed",
                    "allowed_methods": ["GET", "POST"]
                }
        except AuthException as e:
            return 403, {"content-type": "application/json"}, {
                "error": "Forbidden",
                "details": str(e)
            }
        except Exception as e:
            logger.error("azure_config.handler_error",
                        error=str(e),
                        error_type=type(e).__name__,
                        user=auth_info.get('username'))
            return 500, {"content-type": "application/json"}, {
                "error": "Internal server error",
                "details": str(e)
            }
    
    # Handle config endpoints
    if path == "app_config":
        from .server.config_api import get_full_app_config, update_app_config
        
        try:
            if method == "GET":
                config = get_full_app_config(auth_info)
                return 200, {}, config
            elif method == "POST":
                if not request.headers.get("content-type", "").startswith("application/json"):
                    return 400, {"content-type": "application/json"}, {
                        "error": "Invalid content type",
                        "details": "Request must be application/json"
                    }
                
                try:
                    new_config = await request.get_json()
                except ValueError as e:
                    return 400, {"content-type": "application/json"}, {
                        "error": "Invalid JSON",
                        "details": str(e)
                    }
                
                try:
                    # Extract the actual config from the value field
                    if isinstance(new_config, dict) and 'value' in new_config:
                        config_value = new_config['value']
                    else:
                        config_value = new_config
                    
                    updated_config = update_app_config(auth_info, config_value)
                    return 200, {"content-type": "application/json"}, updated_config
                except ValueError as e:
                    return 400, {"content-type": "application/json"}, {
                        "error": "Invalid configuration",
                        "details": str(e)
                    }
            else:
                return 405, {"content-type": "application/json"}, {
                    "error": "Method not allowed",
                    "allowed_methods": ["GET", "POST"]
                }
        except AuthException as e:
            return 403, {"content-type": "application/json"}, {
                "error": "Forbidden",
                "details": str(e)
            }
        except Exception as e:
            logger.error("app_config.handler_error",
                        error=str(e),
                        error_type=type(e).__name__,
                        user=auth_info.get('username'))
            return 500, {"content-type": "application/json"}, {
                "error": "Internal server error",
                "details": str(e)
            }
    
    # Handle other existing endpoints
    return await timetagger.server._apiserver.api_handler_triage(request, path, auth_info, db)


async def get_webtoken(request):
    """Exhange some form of trust for a webtoken."""
    logger.info("get_webtoken called")
    
    try:
        content_type = request.headers.get("content-type", "")
        body = await request.get_body()
        
        # Handle JSON Content-Type
        if content_type.lower().startswith("application/json"):
            logger.info(f"Processing JSON content-type request")
            try:
                auth_info = json.loads(body)
                logger.info(f"JSON Auth info: {auth_info}")
            except Exception as e:
                logger.error(f"Error parsing JSON request body: {str(e)}")
                return 400, {}, f"Bad request: {str(e)}"
        # Handle Base64 encoded body (legacy/default)
        else:
            logger.info(f"Processing Base64 encoded request body")
            try:
                decoded_body = b64decode(body)
                logger.info(f"Decoded body: {decoded_body[:100]}")
                auth_info = json.loads(decoded_body)
                logger.info(f"Base64 Auth info: {auth_info}")
            except Exception as e:
                logger.error(f"Error decoding Base64 request body: {str(e)}")
                return 400, {}, f"Bad request: {str(e)}"
    except Exception as e:
        logger.error(f"Error processing request body: {str(e)}")
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
    print(f"[get_webtoken_azure] Received auth_info: {auth_info}")
    
    # Check if we have a username and access token (from client-side token exchange)
    username = auth_info.get("username", "").strip()
    access_token = auth_info.get("access_token", "").strip()
    
    if username and access_token:
        logger.info(f"[get_webtoken_azure] Using provided username from Azure AD: {username}")
        print(f"[get_webtoken_azure] Using provided username from Azure AD: {username}")
        
        # Check if this is the first user (admin)
        is_admin = False
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
        
        username = id_token_payload.get("preferred_username") or id_token_payload.get("email")
        if not username:
            logger.error("No username or email found in ID token")
            return 403, {}, "forbidden: No username or email found in ID token"
        logger.info(f"Successfully extracted username: {username}")
    except Exception as e:
        logger.error(f"Failed to extract user info from token: {str(e)}")
        return 403, {}, f"forbidden: Failed to extract user info from token: {str(e)}"

    # Return the webtoken for Azure AD user - Set is_admin to False
    token = await get_webtoken_unsafe(username, is_admin=False)
    logger.info("Successfully generated TimeTagger token (via code flow)")
    print(f"[get_webtoken_azure] Generated token (via code flow): {token[:10]}...")
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
    user provides the correct username and password hash as listed in
    the server config (`config.credentials`). See `get_webtoken_unsafe()` for details.
    """
    logger.info("Starting get_webtoken_usernamepassword")
    # Get username and password from request body
    username = auth_info.get("username", "").strip()
    password = auth_info.get("password", "").strip()
    if not (username and password):
        logger.warning("Username or password missing in request")
        return 400, {}, "bad request: username or password missing"
    # Get hash from config
    hash = CREDENTIALS.get(username, "")
    if not hash:
        logger.warning(f"Username '{username}' not found in credentials")
        return 403, {}, "forbidden: invalid credentials"
    # Check the hash!
    # Note that bcrypt handles the salt internally.
    if not bcrypt.checkpw(password.encode(), hash.encode()):
        logger.warning(f"Password check failed for user '{username}'")
        return 403, {}, "forbidden: invalid credentials"
    # Return the webtoken
    logger.info(f"Credentials validated successfully for user '{username}'")
    token = await get_webtoken_unsafe(username)
    logger.info(f"Generated token for user '{username}': {token[:10]}...")
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
    d = {}
    for s in config.credentials.replace(";", ",").split(","):
        name, _, hash = s.partition(":")
        d[name] = hash
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
        print("========== TOKEN EXCHANGE HANDLER CALLED ==========")
        logger.info("Token exchange handler called")
        
        # Get request body
        body_str = await request.get_body()
        print(f"Request body: {body_str}")
        logger.info(f"Request body: {body_str}")
        
        body = json.loads(body_str)
        print(f"Parsed body: {body}")
        logger.info(f"Parsed body: {body}")
        
        code = body.get("code")
        if not code:
            logger.error("No authorization code provided in request")
            print("ERROR: No authorization code provided in request")
            return 400, {}, "Bad request: No authorization code provided"
        
        logger.info(f"Exchanging authorization code (first 10 chars): {code[:10]}...")
        
        # Exchange code for tokens
        # Access the config properties using the right attribute names
        # The environment variables are prefixed with TIMETAGGER_ but the config object might use different naming
        azure_instance = os.environ.get("TIMETAGGER_AZURE_INSTANCE", "https://login.microsoftonline.com")
        azure_tenant_id = os.environ.get("TIMETAGGER_AZURE_TENANT_ID")
        azure_client_id = os.environ.get("TIMETAGGER_AZURE_CLIENT_ID")
        azure_client_secret = os.environ.get("TIMETAGGER_AZURE_CLIENT_SECRET")
        azure_redirect_uri = os.environ.get("TIMETAGGER_AZURE_REDIRECT_URI")
        
        if not azure_tenant_id or not azure_client_id:
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
        
        print(f"Token URL: {token_url}")
        print(f"Final Token request scope: {final_scope}") # Log the final scope
        print(f"Token request data: {token_data}")
        logger.info(f"Token URL: {token_url}")
        logger.info(f"Final Token request scope: {final_scope}") # Log the final scope
        logger.info(f"Token request data: {token_data}")
        
        # Make the token request
        try:
            print("Making token request...")
            async with httpx.AsyncClient() as client:
                # Using httpx to handle form encoding properly
                response = await client.post(
                    token_url,
                    data=token_data,  # httpx will properly format this as application/x-www-form-urlencoded
                    headers={"Content-Type": "application/x-www-form-urlencoded"}
                )
                print(f"Token response status: {response.status_code}")
                print(f"Token response content: {response.text}")
                logger.info(f"Token response status: {response.status_code}")
                logger.info(f"Token response content: {response.text[:200]}")
                
                response.raise_for_status()
                tokens = response.json()
                logger.info("Successfully received tokens from Azure AD")
                
                # Return tokens to the client
                print("Returning tokens to client")
                return 200, {"content-type": "application/json"}, tokens
        except Exception as e:
            print(f"Azure AD token exchange failed: {str(e)}")
            logger.error(f"Azure AD token exchange failed: {str(e)}")
            if hasattr(e, 'response'):
                print(f"Response status: {e.response.status_code}")
                print(f"Response body: {e.response.text}")
                logger.error(f"Response status: {e.response.status_code}")
                logger.error(f"Response body: {e.response.text}")
            return 500, {"content-type": "application/json"}, {"error": f"Azure AD token exchange failed: {str(e)}"}
    except Exception as e:
        print(f"Error in token_exchange_handler: {str(e)}")
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


if __name__ == "__main__":
    asgineer.run(
        "timetagger.__main__:main_handler", "uvicorn", config.bind, log_level="debug"
    )
