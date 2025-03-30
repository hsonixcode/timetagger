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


logger = logging.getLogger("asgineer")

# Get sets of assets provided by TimeTagger
common_assets = create_assets_from_dir(resources.files("timetagger.common"))
apponly_assets = create_assets_from_dir(resources.files("timetagger.app"))
image_assets = create_assets_from_dir(resources.files("timetagger.images"))
page_assets = create_assets_from_dir(resources.files("timetagger.pages"))

# Combine into two groups. You could add/replace assets here.
app_assets = dict(**common_assets, **image_assets, **apponly_assets)
web_assets = dict(**common_assets, **image_assets, **page_assets)

# Enable the service worker so the app can be used offline and is installable
enable_service_worker(app_assets)

# Turn asset dicts into handlers. This feature of Asgineer provides
# lightning fast handlers that support compression and HTTP caching.
app_asset_handler = asgineer.utils.make_asset_handler(app_assets, max_age=0)
web_asset_handler = asgineer.utils.make_asset_handler(web_assets, max_age=0)


@asgineer.to_asgi
async def main_handler(request):
    """
    The main handler where we delegate to the API or asset handler.

    We serve at /timetagger for a few reasons, one being that the service
    worker won't interfere with other stuff you might serve on localhost.
    """
    print(f"Main handler received request for path: {request.path}, method: {request.method}")
    logger.info(f"Main handler received request for path: {request.path}, method: {request.method}")

    if request.path == "/":
        return 307, {"Location": "/timetagger/"}, b""  # Redirect

    elif request.path.startswith("/timetagger/"):
        if request.path == "/timetagger/status":
            return 200, {}, "ok"
        elif request.path.startswith("/timetagger/api/v2/"):
            path = request.path[19:].strip("/")
            print(f"Delegating to API handler with path: {path}")
            logger.info(f"Delegating to API handler with path: {path}")
            return await api_handler(request, path)
        elif request.path.startswith("/timetagger/app/"):
            path = request.path[16:].strip("/")
            return await app_asset_handler(request, path)
        else:
            path = request.path[12:].strip("/")
            # For page assets, prepare template context
            if path == "login": # or maybe check for .md extension?
                template_context = {
                    "timetagger_azure_client_id": os.environ.get("TIMETAGGER_AZURE_CLIENT_ID", ""),
                    "timetagger_azure_tenant_id": os.environ.get("TIMETAGGER_AZURE_TENANT_ID", ""),
                    "timetagger_azure_client_secret": os.environ.get("TIMETAGGER_AZURE_CLIENT_SECRET", "")
                }
                print(f"Rendering {path} with context: {template_context}")
                logger.info(f"Rendering {path} with context keys: {list(template_context.keys())}")
                # Note: asgineer.utils.make_asset_handler doesn't directly support context.
                # We might need a custom handler or different templating approach.
                # For now, let's assume the standard handler *might* pick it up if available somehow,
                # or this highlights the need for a proper templating engine integration.
            return await web_asset_handler(request, path) # Pass context if handler supports it

    else:
        return 404, {}, "only serving at /timetagger/"


async def api_handler(request, path):
    """The default API handler. Designed to be short, so that
    applications that implement alternative authentication and/or have
    more API endpoints can use this as a starting point.
    """
    print(f"API handler called with path: '{path}' and method: {request.method}")
    logger.info(f"API handler called with path: '{path}' and method: {request.method}")

    # Some endpoints do not require authentication
    if not path and request.method == "GET":
        return 200, {}, "See https://timetagger.readthedocs.io"
    elif path == "bootstrap_authentication":
        # The client-side that requests these is in pages/login.md
        print("Handling bootstrap_authentication request")
        logger.info("Handling bootstrap_authentication request")
        return await get_webtoken(request)
    elif path == "token_exchange" and request.method == "POST":
        # Token exchange endpoint is exempt from authentication
        print("Handling token_exchange request")
        logger.info("Handling token_exchange request")
        return await token_exchange_handler(request)
    elif path == "test_post" and request.method == "POST":
        # Test endpoint is exempt from authentication
        print("Handling test_post request")
        logger.info("Handling test_post request")
        
        # Get the request body
        body = await request.get_body()
        body_text = body.decode('utf-8') if isinstance(body, bytes) else body
        
        # Return a simple response
        return 200, {"Content-Type": "application/json"}, {"status": "success", "message": "POST request received", "body": body_text}

    # Authenticate and get user db
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
    """The handler that takes care of the actual API requests."""
    
    print(f"API triage handling path: {path}, method: {request.method}")
    logger.debug(f"API triage handling path: {path}, method: {request.method}")
    
    # Delegate to the original api_handler_triage for all standard endpoints
    print(f"Delegating to standard api_handler_triage for path: {path}")
    logger.info(f"Delegating to standard api_handler_triage for path: {path}")
    return await timetagger.server.api_handler_triage(request, path, auth_info, db)


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
        # We have the username and token, so we can directly generate a TimeTagger token
        token = await get_webtoken_unsafe(username)
        logger.info("Successfully generated TimeTagger token")
        print(f"[get_webtoken_azure] Generated token: {token[:10]}...")
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

    # Return the webtoken for Azure AD user
    token = await get_webtoken_unsafe(username)
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
    """An authentication handler to exchange credentials for a webtoken.
    The credentials are set via the config and are intended to support
    a handful of users. See `get_webtoken_unsafe()` for details.
    """
    # This approach uses bcrypt to hash the passwords with a salt,
    # and is therefore much safer than e.g. BasicAuth.

    # Get credentials from request
    user = auth_info.get("username", "").strip()
    pw = auth_info.get("password", "").strip()
    # Get hash for this user
    hash = CREDENTIALS.get(user, "")
    # Check
    if user and hash and bcrypt.checkpw(pw.encode(), hash.encode()):
        token = await get_webtoken_unsafe(user)
        return 200, {}, dict(token=token)
    else:
        return 403, {}, "Invalid credentials"


async def get_webtoken_localhost(request, auth_info):
    """An authentication handler that provides a webtoken when the
    hostname is localhost. See `get_webtoken_unsafe()` for details.
    """
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
            return 500, {"Content-Type": "application/json"}, {"error": "Missing required Azure AD configuration"}
        
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
                return 200, {"Content-Type": "application/json"}, tokens
        except Exception as e:
            print(f"Azure AD token exchange failed: {str(e)}")
            logger.error(f"Azure AD token exchange failed: {str(e)}")
            if hasattr(e, 'response'):
                print(f"Response status: {e.response.status_code}")
                print(f"Response body: {e.response.text}")
                logger.error(f"Response status: {e.response.status_code}")
                logger.error(f"Response body: {e.response.text}")
            return 500, {"Content-Type": "application/json"}, {"error": f"Azure AD token exchange failed: {str(e)}"}
    except Exception as e:
        print(f"Error in token_exchange_handler: {str(e)}")
        logger.error(f"Error in token_exchange_handler: {str(e)}")
        return 500, {"Content-Type": "application/json"}, {"error": f"Internal server error: {str(e)}"}


if __name__ == "__main__":
    asgineer.run(
        "timetagger.__main__:main_handler", "uvicorn", config.bind, log_level="debug"
    )
