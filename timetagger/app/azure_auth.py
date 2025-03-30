"""
Azure AD authentication integration for TimeTagger.
"""

from pscript.stubs import window, JSON, localStorage, location, console, fetch

class AzureAuth:
    def __init__(self):
        self.client_id = window.AZURE_CLIENT_ID
        self.tenant_id = window.AZURE_TENANT_ID
        self.redirect_uri = window.AZURE_REDIRECT_URI
        self.authority = f"https://login.microsoftonline.com/{self.tenant_id}"
        self.scope = "openid profile email https://graph.microsoft.com/User.Read"
        
    async def login(self):
        """Initiate Azure AD login flow."""
        try:
            # Generate state for CSRF protection
            state = window.crypto.randomUUID()
            localStorage.setItem("azure_auth_state", state)
            
            # Build authorization URL
            auth_url = f"{this.authority}/oauth2/v2.0/authorize"
            params = {
                "client_id": this.client_id,
                "response_type": "code",
                "redirect_uri": this.redirect_uri,
                "response_mode": "query",
                "scope": this.scope,
                "state": state
            }
            
            # Redirect to Azure AD login
            location.href = auth_url + "?" + "&".join([f"{k}={window.encodeURIComponent(v)}" for k, v in params.items()])
            
        except Exception as e:
            console.error("Azure AD login failed:", e)
            raise Error(f"Azure AD login failed: {str(e)}")
            
    async def handle_callback(self):
        """Handle the Azure AD callback with authorization code."""
        try:
            # Get URL parameters
            params = window.url2dict(location.search)
            
            # Verify state
            state = localStorage.getItem("azure_auth_state")
            if not state or state != params.get("state"):
                raise Error("Invalid state parameter")
                
            # Get authorization code
            code = params.get("code")
            if not code:
                raise Error("No authorization code received")
                
            # Exchange code for tokens
            token_url = f"{this.authority}/oauth2/v2.0/token"
            token_data = {
                "client_id": this.client_id,
                "code": code,
                "redirect_uri": this.redirect_uri,
                "grant_type": "authorization_code"
            }
            
            response = await fetch(token_url, {
                "method": "POST",
                "headers": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "body": window.dict2url(token_data)
            })
            
            if not response.ok:
                raise Error(f"Token request failed: {await response.text()}")
                
            tokens = await response.json()
            
            # Store Azure tokens
            localStorage.setItem("azure_access_token", tokens["access_token"])
            localStorage.setItem("azure_id_token", tokens["id_token"])
            
            # Get user info from ID token
            id_token_parts = tokens["id_token"].split('.')
            id_token_payload = JSON.parse(window.atob(id_token_parts[1]))
            username = id_token_payload["preferred_username"]
            
            # Exchange Azure token for TimeTagger webtoken
            auth_info = {
                "method": "azure",
                "username": username,
                "access_token": tokens["access_token"]
            }
            
            response = await fetch("/timetagger/api/v2/bootstrap_authentication", {
                "method": "POST",
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": JSON.stringify(auth_info)
            })
            
            if not response.ok:
                raise Error(f"Failed to get TimeTagger token: {await response.text()}")
                
            tt_token = await response.json()
            window.tools.set_auth_info_from_token(tt_token["token"])
            
            # Redirect back to app
            location.href = "/timetagger/app/"
            
        except Exception as e:
            console.error("Azure AD callback handling failed:", e)
            raise Error(f"Azure AD callback handling failed: {str(e)}")
            
    async def get_access_token(self):
        """Get the current access token."""
        return localStorage.getItem("azure_access_token")
        
    async def logout(self):
        """Logout from Azure AD."""
        try:
            # Clear tokens
            localStorage.removeItem("azure_access_token")
            localStorage.removeItem("azure_id_token")
            localStorage.removeItem("azure_auth_state")
            
            # Redirect to Azure AD logout
            logout_url = f"{this.authority}/oauth2/v2.0/logout"
            params = {
                "post_logout_redirect_uri": window.location.origin + "/timetagger/pages/login"
            }
            location.href = logout_url + "?" + "&".join([f"{k}={window.encodeURIComponent(v)}" for k, v in params.items()])
            
        except Exception as e:
            console.error("Azure AD logout failed:", e)
            raise Error(f"Azure AD logout failed: {str(e)}") 