% Time Tracker - Login
% The Time Tracker application.

<script>
// Set Azure AD configuration variables
window.AZURE_CLIENT_ID = '{{ timetagger_azure_client_id }}';
window.AZURE_TENANT_ID = '{{ timetagger_azure_tenant_id }}';
window.AZURE_REDIRECT_URI = 'http://localhost:8000/timetagger/login';
window.AZURE_CLIENT_SECRET = '{{ timetagger_azure_client_secret }}';

// Initialize Azure AD configuration
const azureConfig = {
    clientId: window.AZURE_CLIENT_ID,
    tenantId: window.AZURE_TENANT_ID,
    redirectUri: window.AZURE_REDIRECT_URI,
    clientSecret: window.AZURE_CLIENT_SECRET,
    get authority() {
        if (!this.tenantId) {
            throw new Error('Azure AD tenant ID is not configured');
        }
        return `https://login.microsoftonline.com/${this.tenantId}`;
    },
    get scope() {
        if (!this.clientId) {
            throw new Error('Azure AD client ID is not configured');
        }
        // Use GUID format for the scope when requesting token for the app itself
        return `${this.clientId}/.default`;
    }
};

// Azure AD auth handler
class AzureAuthHandler {
    constructor(config) {
        this.config = config;
    }
    
    async login() {
        try {
            // Validate configuration
            if (!this.config.clientId) {
                throw new Error('Azure AD client ID is not configured');
            }
            if (!this.config.tenantId) {
                throw new Error('Azure AD tenant ID is not configured');
            }
            if (!this.config.clientSecret) {
                console.warn('Azure AD client secret is missing - this may cause authentication to fail');
            }
            
            // Store the original page URL
            const originalPage = document.referrer || '/timetagger/app/';
            localStorage.setItem("azure_original_page", originalPage);
            
            // Generate state for CSRF protection
            const state = window.crypto.randomUUID();
            localStorage.setItem("azure_auth_state", state);
            
            // Build authorization URL
            const authUrl = `${this.config.authority}/oauth2/v2.0/authorize`;
            const params = {
                client_id: this.config.clientId,
                response_type: "code",
                redirect_uri: this.config.redirectUri,
                response_mode: "query",
                scope: this.config.scope,
                state: state
            };
            
            // Redirect to Azure AD login
            window.location.href = authUrl + "?" + Object.entries(params)
                .map(([k, v]) => `${k}=${encodeURIComponent(v)}`)
                .join("&");
            
        } catch (error) {
            console.error("Azure AD login failed:", error);
            throw new Error(`Azure AD login failed: ${error.message}`);
        }
    }
    
    async handleCallback(code, state) {
        console.log("Processing authorization code");
        
        // Check if the state matches
        const storedState = localStorage.getItem('azure_auth_state');
        
        if (!code || !state) {
            console.error("handleCallback called without code or state argument");
            this.updateStatus('Azure AD authentication failed - missing params', 'error');
            return;
        }
        
        if (state !== storedState) {
            console.error("State mismatch - possible CSRF attack");
            this.updateStatus('Azure AD authentication failed - state mismatch', 'error');
            return;
        }
        
        try {
            console.log("Preparing to exchange code for tokens");
            const tokenData = {
                code: code,
                redirect_uri: this.config.redirectUri,
                client_id: this.config.clientId,
                client_secret: this.config.clientSecret,
                scope: this.config.scope,
                grant_type: 'authorization_code'
            };
            
            try {
                const response = await fetch('/timetagger/api/v2/token_exchange', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(tokenData)
                });
                
                if (!response.ok) {
                    const errorText = await response.text();
                    console.error(`Token exchange failed: ${errorText}`);
                    this.updateStatus('Azure AD authentication failed - token exchange error', 'error');
                    return;
                }
                
                const tokens = await response.json();
                console.log("Token exchange successful");
                
                // Process and store tokens
                await this.processTokens(tokens);
                
            } catch (error) {
                console.error('Error during fetch:', error);
                this.updateStatus('Azure AD authentication failed - error during token exchange', 'error');
            }
        } catch (error) {
            console.error('Error during callback:', error);
            this.updateStatus('Azure AD authentication failed - error during token exchange', 'error');
        }
    }

    // Process and store tokens received from the token exchange
    async processTokens(tokens) {
        console.log('Processing tokens from token exchange');
        
        // Store the tokens
        if (tokens.access_token) {
            localStorage.setItem('azure_access_token', tokens.access_token);
            console.log('Access token stored');
        }
        
        if (tokens.id_token) {
            localStorage.setItem('azure_id_token', tokens.id_token);
            console.log('ID token stored');
            
            // Parse user info from ID token
            try {
                const idTokenParts = tokens.id_token.split('.');
                const base64Url = idTokenParts[1];
                const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
                const padded = base64 + '==='.slice(0, (4 - base64.length % 4) % 4);
                const payload = JSON.parse(atob(padded));
                
                // Use the username from the ID token for TimeTagger authentication
                if (payload.preferred_username || payload.email) {
                    const username = payload.preferred_username || payload.email;
                    console.log('Using username from ID token:', username);
                    
                    // Authenticate with TimeTagger using the username and access token
                    await this.authenticateWithTimeTagger(username, tokens.access_token);
                } else {
                    console.error('No username or email found in ID token');
                    this.updateStatus('No username found in ID token', 'error');
                }
            } catch (error) {
                console.error('Error parsing ID token:', error);
                this.updateStatus('Error parsing ID token', 'error');
            }
        }
        
        if (tokens.refresh_token) {
            localStorage.setItem('azure_refresh_token', tokens.refresh_token);
            console.log('Refresh token stored');
        }
        
        if (tokens.expires_in) {
            const expiresAt = Date.now() + (tokens.expires_in * 1000);
            localStorage.setItem('azure_token_expires_at', expiresAt.toString());
            console.log(`Token expiration set: ${new Date(expiresAt).toLocaleString()}`);
        }
        
        // Clean up state after successful authentication
        localStorage.removeItem('azure_auth_state');
        
        // Update token status
        checkTokenStatus();
        
        // Redirect to original page if available
        const originalPage = localStorage.getItem('azure_original_page');
        if (originalPage) {
            console.log(`Redirecting to original page: ${originalPage}`);
            localStorage.removeItem('azure_original_page');
            window.location.href = originalPage;
        } else {
            console.log('No original page found, redirecting to account page');
            window.location.href = '/timetagger/app/';
        }
    }

    // Authenticate with TimeTagger using username from Azure AD
    async authenticateWithTimeTagger(username, accessToken) {
        console.log(`Authenticating with TimeTagger as: ${username}`);
        
        try {
            // Base64 encode the auth info
            const authInfo = {
                method: 'azure',
                username: username,
                access_token: accessToken
            };
            
            const authInfoStr = JSON.stringify(authInfo);
            const authInfoBase64 = btoa(authInfoStr);
            
            console.log('Sending authentication request to TimeTagger');
            
            // Send authentication request
            const response = await fetch('/timetagger/api/v2/bootstrap_authentication', {
                method: 'POST',
                body: authInfoBase64
            });
            
            if (!response.ok) {
                const errorText = await response.text();
                console.error(`TimeTagger authentication failed: ${errorText}`);
                this.updateStatus('TimeTagger authentication failed', 'error');
                return;
            }
            
            const data = await response.json();
            
            if (data && data.token) {
                console.log('TimeTagger authentication successful, token received');
                
                // --- Use the correct function from tools.js --- 
                if (typeof window.tools?.set_auth_info_from_token === 'function') {
                    try {
                        debugLog("[Login Page] Attempting to call tools.set_auth_info_from_token()...");
                        window.tools.set_auth_info_from_token(data.token);
                        debugLog("[Login Page] Call to tools.set_auth_info_from_token() completed.");
                        
                        // Verify immediately what was stored
                        const storedAuth = localStorage.getItem("timetagger_auth_info");
                        if (storedAuth) {
                            debugLog(`[Login Page] Verified storage: timetagger_auth_info = ${storedAuth.substring(0, 50)}...`, "success");
                        } else {
                            debugLog("[Login Page] VERIFICATION FAILED: timetagger_auth_info NOT found in localStorage immediately after setting!", "error");
                        }
                    } catch (e) {
                        console.error("[Login Page] Error calling tools.set_auth_info_from_token:", e);
                        // Store raw token as fallback if setting fails
                        localStorage.setItem('timetagger_token', data.token);
                        debugLog(`[Login Page] Stored raw timetagger_token as fallback: ${data.token.substring(0, 10)}...`);
                    }
                } else {
                     debugLog("[Login Page] window.tools.set_auth_info_from_token function not available.", "error");
                     // Fallback - store raw token (though app might not read it)
                     localStorage.setItem('timetagger_token', data.token);
                     debugLog(`[Login Page] Stored raw timetagger_token as fallback: ${data.token.substring(0, 10)}...`);
                }
                // --- End correct function usage --- 
                
                this.updateStatus('TimeTagger authentication successful', 'success');
            } else {
                console.error('No token received from TimeTagger');
                this.updateStatus('No token received from TimeTagger', 'error');
            }
        } catch (error) {
            console.error('Error during TimeTagger authentication:', error);
            this.updateStatus('Error during TimeTagger authentication', 'error');
        }
    }

    // Update status message with type (success, error, info)
    updateStatus(message, type = 'info') {
        console.log(`Status update (${type}): ${message}`);
        
        const statusElement = document.createElement('div');
        statusElement.className = `token-status ${type}`;
        statusElement.textContent = message;
        
        // Clear existing status messages of the same type
        document.querySelectorAll(`.token-status.${type}`).forEach(el => el.remove());
        
        // Add the new status message
        document.getElementById('token-status-container').appendChild(statusElement);
    }
}

// Initialize Azure AD auth handler
const azureAuth = new AzureAuthHandler(azureConfig);

// Log URL immediately on script start, before 'load' event
console.log("[EARLY LOG] Initial window.location.href:", window.location.href);

// --- Check for callback parameters *immediately* ---
const initialUrlParams = new URLSearchParams(window.location.search);
const initialCode = initialUrlParams.get('code');
const initialState = initialUrlParams.get('state');
let isInCallbackMode = initialCode && initialState;
if (isInCallbackMode) {
    console.log("[IMMEDIATE CHECK] Determined to be in callback mode.");
} else {
    console.log("[IMMEDIATE CHECK] Determined NOT to be in callback mode.");
}
// --- End immediate check ---

// Initialize on page load
window.addEventListener('load', async function() {
    const statusEl = document.getElementById('status');
    const loginButton = document.querySelector('button');
    
    try {
        if (statusEl) statusEl.textContent = 'Loading required scripts...';
        
        // Define scripts to load
        const scripts = [
             '/timetagger/app/tools.js',
             '/timetagger/app/utils.js',
             '/timetagger/app/dt.js',
             '/timetagger/app/stores.js',
             '/timetagger/app/dialogs.js',
             '/timetagger/app/front.js',
             // azure_auth.js is not needed as the class is defined inline now
        ];
        
        // Load scripts first
        await loadScriptSequentially(scripts);

        // Wait for scripts (especially tools.js) to initialize
        if (statusEl) statusEl.textContent = 'Initializing tools...';
        await waitForScripts(); 

        // --- Now that scripts are loaded, proceed with auth logic --- 

        // Setup global login handler (needs AzureAuthHandler class)
        window.handleAzureLogin = async function() {
            try {
                // Use the globally defined azureAuth instance
                await azureAuth.login(); 
            } catch (error) {
                console.error('Login failed:', error);
                alert(`Login failed: ${error.message}`);
            }
        };

        // Check if we determined we are in callback mode earlier
        if (isInCallbackMode) {
            // We have an auth code and state, we're in the callback process
            console.log("Processing callback based on immediate check.");
            if (statusEl) statusEl.textContent = 'Processing Azure AD login...';
            if (loginButton) loginButton.disabled = true;
            
            // Process callback - PASS initialCode and initialState
            await azureAuth.handleCallback(initialCode, initialState); 
        } else {
            // Not in a callback state, enable login button
            console.log("Not in callback mode (based on immediate check).");
            if (statusEl) statusEl.textContent = 'Ready to login';
            if (loginButton) loginButton.disabled = false;
        }
        
        // Check token status *after* potential callback processing
        checkTokenStatus();
        
    } catch (error) {
        console.error('Initialization failed:', error);
        if (statusEl) {
            statusEl.textContent = `Failed to initialize: ${error.message}. Please check console.`;
        }
        // Ensure button is usable if init fails
        if (loginButton) loginButton.disabled = false; 
    }
});

// Function to load scripts sequentially
async function loadScriptSequentially(scripts) {
    for (const script of scripts) {
        try {
            console.log('Loading script:', script);
            await new Promise((resolve, reject) => {
                const scriptEl = document.createElement('script');
                scriptEl.src = script;
                scriptEl.onload = () => {
                    console.log('Successfully loaded:', script);
                    resolve();
                };
                scriptEl.onerror = (event) => {
                    console.error('Failed to load script:', script, event);
                    reject(new Error(`Failed to load script: ${script} (${event.type})`));
                };
                document.head.appendChild(scriptEl);
            });
            
            // Add a small delay after loading dt.js to ensure it's initialized
            if (script.includes('dt.js')) {
                await new Promise(resolve => setTimeout(resolve, 200));
            }
        } catch (error) {
            console.error('Script loading error:', error);
            const statusEl = document.getElementById('status');
            if (statusEl) {
                statusEl.textContent = `Failed to load script: ${error.message}`;
            }
            throw error;
        }
    }
}

// Function to check if scripts are loaded
async function waitForScripts() {
    // Wait for tools to be available
    let attempts = 0;
    while (!window.tools && attempts < 50) {
        await new Promise(resolve => setTimeout(resolve, 100));
        attempts++;
    }
    if (!window.tools) {
        throw new Error('Failed to initialize tools');
    }
}

// Function to check token status
function checkTokenStatus() {
    console.log('Checking token status...');
    
    // Check Azure AD tokens
    const azureTokenStatusEl = document.getElementById('azure-token-status');
    const azureAccessToken = localStorage.getItem("azure_access_token");
    const azureIdToken = localStorage.getItem("azure_id_token");
    const azureRefreshToken = localStorage.getItem("azure_refresh_token");
    const azureTokenExpiresAt = localStorage.getItem("azure_token_expires_at");
    const azureAuthCode = localStorage.getItem("azure_auth_code");
    
    console.log('Azure AD tokens:', {
        accessToken: azureAccessToken ? 'Present' : 'Missing',
        idToken: azureIdToken ? 'Present' : 'Missing',
        refreshToken: azureRefreshToken ? 'Present' : 'Missing',
        authCode: azureAuthCode ? 'Present' : 'Missing'
    });
    
    // If we have a code in the URL, we're in the callback process
    const isCallback = window.location.search.includes('code=');
    
    if (isCallback) {
        azureTokenStatusEl.textContent = '⏳ Processing Azure AD login...';
        azureTokenStatusEl.className = 'token-status processing';
    } else if (azureAccessToken && azureIdToken) {
        // Check if tokens are expired
        let tokenStatus = '✓ Azure AD Authenticated';
        if (azureTokenExpiresAt) {
            const expiresAt = parseInt(azureTokenExpiresAt, 10);
            const now = Date.now();
            if (expiresAt < now) {
                tokenStatus += ' (Tokens expired)';
            } else {
                const minutesRemaining = Math.floor((expiresAt - now) / (1000 * 60));
                tokenStatus += ` (Expires in ${minutesRemaining} minutes)`;
            }
        }
        azureTokenStatusEl.textContent = tokenStatus;
        azureTokenStatusEl.className = 'token-status authenticated';
    } else if (azureAuthCode) {
        azureTokenStatusEl.textContent = '✓ Azure AD Code Received (Tokens pending)';
        azureTokenStatusEl.className = 'token-status authenticated';
    } else {
        azureTokenStatusEl.textContent = '✗ Azure AD Not authenticated';
        azureTokenStatusEl.className = 'token-status not-authenticated';
    }
    
    // Check TimeTagger token
    const ttTokenStatusEl = document.getElementById('tt-token-status');
    
    // Log tools availability
    console.log('Checking TimeTagger tools:', {
        toolsAvailable: typeof window.tools !== 'undefined',
        getAuthInfoAvailable: window.tools && typeof window.tools.get_auth_info === 'function'
    });
    
    let ttToken = null;
    try {
        if (window.tools && typeof window.tools.get_auth_info === 'function') {
            ttToken = window.tools.get_auth_info();
            console.log('TimeTagger token:', ttToken ? 'Present' : 'Missing');
            if (ttToken) {
                console.log('Token details:', ttToken);
            }
        } else {
            console.error('tools.get_auth_info is not available');
        }
    } catch (error) {
        console.error('Error getting TimeTagger token:', error);
    }
    
    if (isCallback) {
        ttTokenStatusEl.textContent = '⏳ Processing TimeTagger login...';
        ttTokenStatusEl.className = 'token-status processing';
    } else if (ttToken) {
        ttTokenStatusEl.textContent = '✓ TimeTagger Authenticated';
        ttTokenStatusEl.className = 'token-status authenticated';
    } else {
        ttTokenStatusEl.textContent = '✗ TimeTagger Not authenticated';
        ttTokenStatusEl.className = 'token-status not-authenticated';
    }
}

// Helper function to log to both console and debug display
function debugLog(message, type = 'info') {
    // Log to console
    console.log(message);
    
    // Log to debug display
    const debugOutput = document.getElementById('debug-output');
    if (debugOutput) {
        const entry = document.createElement('div');
        entry.className = `debug-entry ${type}`;
        entry.textContent = `${new Date().toISOString().slice(11, 23)} [${type.toUpperCase()}] ${message}`;
        debugOutput.appendChild(entry);
        
        // Auto-scroll to bottom
        debugOutput.scrollTop = debugOutput.scrollHeight;
        
        // Show debug container if hidden
        const debugContainer = document.getElementById('debug-container');
        if (debugContainer) {
            debugContainer.style.display = 'block';
        }
    }
}
</script>

<div class="login-container">
    <h1>Time Tracker Login</h1>
    <div id="status">Initializing...</div>
    <button onclick="window.handleAzureLogin()">Login with Azure AD</button>
    <div id="error-message" class="error-message"></div>
    
    <div id="token-status-container" class="token-status-container">
        <div id="azure-token-status" class="token-status"></div>
        <div id="tt-token-status" class="token-status"></div>
    </div>
</div>

<style>
.login-container {
    max-width: 400px;
    margin: 100px auto;
    padding: 20px;
    text-align: center;
    background: white;
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.error-message {
    color: #d13438;
    background-color: #fff3f3;
    padding: 10px;
    margin: 10px 0;
    border-radius: 4px;
    border: 1px solid #d13438;
    font-size: 14px;
    display: none;
}

.error-message:not(:empty) {
    display: block;
}

button {
    background-color: #0078d4;
    color: white;
    border: none;
    padding: 12px 24px;
    border-radius: 4px;
    cursor: pointer;
    font-size: 16px;
    margin-top: 20px;
    transition: background-color 0.2s;
}

button:hover:not(:disabled) {
    background-color: #106ebe;
}

button:active:not(:disabled) {
    background-color: #005a9e;
}

button:disabled {
    background-color: #ccc;
    cursor: not-allowed;
}

#status {
    margin: 20px 0;
    color: #666;
    font-size: 14px;
}

.token-status-container {
    margin-top: 15px;
    display: flex;
    flex-direction: column;
    gap: 10px;
}

.token-status {
    padding: 10px;
    border-radius: 4px;
    font-size: 14px;
    display: flex;
    align-items: center;
    justify-content: center;
}

.token-status.authenticated {
    background-color: #e6f3ff;
    color: #0078d4;
    border: 1px solid #0078d4;
}

.token-status.not-authenticated {
    background-color: #fff3f3;
    color: #d13438;
    border: 1px solid #d13438;
}

.token-status.processing {
    background-color: #fff3e0;
    color: #f57c00;
    border: 1px solid #f57c00;
}

.token-status.success {
    background-color: #e6f7e6;
    color: #107c10;
    border: 1px solid #107c10;
}

.token-status.error {
    background-color: #fff3f3;
    color: #d13438;
    border: 1px solid #d13438;
}

h1 {
    color: #333;
    margin-bottom: 30px;
}
</style>

