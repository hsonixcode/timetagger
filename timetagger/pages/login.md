% Time Tracker - Login
% The Time Tracker application.

<div id="login-form" style="padding: 2em; border: 1px solid #ccc; border-radius: 5px; max-width: 400px; margin: 2em auto;">
    <h2>Login</h2>
    <p id="login-status" style="color: red;"></p>

    <div id="credential-login" style="margin-bottom: 1em;">
        <label for="username">Username:</label><br>
        <input type="text" id="username" name="username" style="width: 95%; padding: 8px; margin-bottom: 10px;"><br>
        <label for="password">Password:</label><br>
        <input type="password" id="password" name="password" style="width: 95%; padding: 8px; margin-bottom: 10px;"><br>
        <button id="login-button" onclick="handleCredentialLogin(event)" style="padding: 10px 15px;">Login</button>
    </div>

    <div id="azure-login" style="margin-top: 1em; border-top: 1px solid #ccc; padding-top: 1em;">
        <p>Or login with:</p>
        <button id="azure-login-button" onclick="handleAzureLogin()" style="padding: 10px 15px;">Azure Active Directory</button> 
        <!-- Note: The handleAzureLogin function needs to be defined globally or attached correctly -->
    </div>

    <div id="token-status" style="margin-top: 1em; border-top: 1px solid #ccc; padding-top: 1em; font-size: 0.9em;">
        <h3>Token Status</h3>
        <div id="azure-token-status" style="margin-bottom: 1em;">
            <strong>Azure AD Tokens:</strong><br>
            <pre id="azure-token-details" style="white-space: pre-wrap; word-break: break-all;"></pre>
        </div>
        <div id="timetagger-token-status">
            <strong>TimeTagger Token:</strong><br>
            <pre id="timetagger-token-details" style="white-space: pre-wrap; word-break: break-all;"></pre>
        </div>
    </div>
</div>

<script>
// Remove placeholder window variables - config will come from API
// window.AZURE_CLIENT_ID = '{{ timetagger_azure_client_id }}';
// window.AZURE_TENANT_ID = '{{ timetagger_azure_tenant_id }}';
// window.AZURE_REDIRECT_URI = '{{ timetagger_azure_redirect_uri }}';
// window.AZURE_CLIENT_SECRET = '{{ timetagger_azure_client_secret }}';

// Azure AD auth handler class definition - MOVED TO TOP
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
            updateStatus('Azure AD login failed: ' + error.message, 'error');
            throw error;
        }
    }
    
    async handleCallback(code, state) {
        console.log("Processing authorization code with state validation");
        
        // Check if the state matches
        const storedState = localStorage.getItem('azure_auth_state');
        console.log("State validation:", {
            receivedState: state,
            storedState: storedState,
            matches: state === storedState,
            hasStoredState: !!storedState
        });
        
        if (!code || !state) {
            console.error("handleCallback called without code or state argument", {
                hasCode: !!code,
                hasState: !!state
            });
            this.updateStatus('Azure AD authentication failed - missing params', 'error');
            return;
        }
        
        if (state !== storedState) {
            console.error("State mismatch - possible CSRF attack", {
                receivedState: state,
                storedState: storedState
            });
            this.updateStatus('Azure AD authentication failed - state mismatch', 'error');
            return;
        }
        
        try {
            console.log("Preparing to exchange code for tokens", {
                redirectUri: this.config.redirectUri,
                clientId: this.config.clientId,
                hasClientSecret: !!this.config.clientSecret,
                scope: this.config.scope,
                authority: this.config.authority
            });
            
            const tokenData = {
                code: code,
                redirect_uri: this.config.redirectUri,
                client_id: this.config.clientId,
                client_secret: this.config.clientSecret,
                scope: this.config.scope,
                grant_type: 'authorization_code'
            };
            
            console.log("Token exchange request payload:", {
                ...tokenData,
                client_secret: '[REDACTED]'
            });
            
            try {
                console.log("Sending token exchange request to:", '/timetagger/api/v2/token_exchange');
                const response = await fetch('/timetagger/api/v2/token_exchange', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(tokenData)
                });
                
                console.log("Token exchange response:", {
                    status: response.status,
                    statusText: response.statusText,
                    headers: Object.fromEntries(response.headers)
                });
                
                if (!response.ok) {
                    const errorText = await response.text();
                    console.error("Token exchange failed:", {
                        status: response.status,
                        statusText: response.statusText,
                        error: errorText
                    });
                    this.updateStatus('Azure AD authentication failed - token exchange error', 'error');
                    return;
                }
                
                const tokens = await response.json();
                console.log("Token exchange successful", {
                    hasAccessToken: !!tokens.access_token,
                    hasIdToken: !!tokens.id_token,
                    hasRefreshToken: !!tokens.refresh_token,
                    expiresIn: tokens.expires_in
                });
                
                // Process and store tokens
                await this.processTokens(tokens);
                
            } catch (error) {
                console.error('Error during token exchange:', error);
                this.updateStatus('Azure AD authentication failed - error during token exchange', 'error');
                throw error;
            }
        } catch (error) {
            console.error('Error during callback processing:', error);
            this.updateStatus('Azure AD authentication failed - error during token exchange', 'error');
            throw error;
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
                
                // Update token status
                await validateTokens();
                
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
                
                // Store the token using tools.js
                if (typeof window.tools?.set_auth_info_from_token === 'function') {
                    window.tools.set_auth_info_from_token(data.token);
                    console.log('Token stored successfully');
                    
                    // Update status and redirect
                    this.updateStatus('Authentication successful, redirecting...', 'success');
                    
                    // Get the original page URL or default to the app page
                    const originalPage = localStorage.getItem('azure_original_page') || '/timetagger/app/';
                    console.log(`Will redirect to: ${originalPage}`);
                    
                    // Clean up the original page from storage
                    localStorage.removeItem('azure_original_page');
                    
                    // Short delay to ensure token is stored and status is shown
                    setTimeout(() => {
                        console.log('Redirecting to:', originalPage);
                        window.location.href = originalPage;
                    }, 1000);
                } else {
                    console.error('tools.set_auth_info_from_token not available');
                    this.updateStatus('Error storing authentication token', 'error');
                }
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
        
        // Update the status element
        const statusEl = document.getElementById('status');
        if (statusEl) {
            statusEl.textContent = message;
            statusEl.className = type;
        }
        
        // Update token status elements based on type
        if (type === 'error') {
            const errorEl = document.getElementById('error-message');
            if (errorEl) {
                errorEl.textContent = message;
                errorEl.style.display = 'block';
            }
        }
    }
}

// Single azureConfig declaration with empty initial values
const azureConfig = {
    clientId: '',
    tenantId: '',
    redirectUri: '', // Will be set from backend config
    
    get authority() {
        if (!this.tenantId) {
            console.warn('Azure AD tenant ID is not configured.');
            return '';
        }
        return `https://login.microsoftonline.com/${this.tenantId}`;
    },
    get scope() {
        if (!this.clientId) {
            console.warn('Azure AD client ID is not configured.');
            return 'openid profile email';
        }
        return `openid profile email ${this.clientId}/.default`;
    }
};

// Azure AD auth handler - instantiate with initial empty config
const azureAuthHandler = new AzureAuthHandler(azureConfig);

// Log the initial (empty) config state
console.log("Azure Config Initial Structure:", azureConfig);

// Initialize on page load
window.addEventListener('load', async function() {
    const statusEl = document.getElementById('login-status');
    const credentialLoginButton = document.getElementById('login-button');
    const azureLoginSection = document.getElementById('azure-login');
    const azureLoginButton = document.getElementById('azure-login-button');

    // Hide Azure section initially
    if(azureLoginSection) azureLoginSection.style.display = 'none';

    try {
        if (statusEl) statusEl.textContent = 'Loading scripts and configuration...';
        
        // Load required scripts first
        await loadScriptSequentially([
            '/timetagger/app/tools.js',       
            '/timetagger/app/utils.js',      
            '/timetagger/app/dt.js',         
            '/timetagger/app/stores.js',     
            '/timetagger/app/dialogs.js',    
            '/timetagger/app/front.js'       
        ]);

        // Wait for scripts to initialize
        if (statusEl) statusEl.textContent = 'Initializing tools...';
        await waitForScripts();

        // Fetch public auth config from our new API endpoint
        if (statusEl) statusEl.textContent = 'Fetching authentication configuration...';
        try {
            const response = await fetch('/timetagger/api/v2/public_auth_config');
            if (!response.ok) {
                throw new Error(`Failed to fetch auth config: ${response.status} ${await response.text()}`);
            }
            
            const publicAuthConfig = await response.json();
            console.log("Public Auth Config fetched:", publicAuthConfig);
            
            // Update azureConfig with values from the API
            if (publicAuthConfig.azure_auth_enabled) {
                azureConfig.clientId = publicAuthConfig.azure_client_id;
                azureConfig.tenantId = publicAuthConfig.azure_tenant_id;
                azureConfig.redirectUri = publicAuthConfig.azure_redirect_uri;
                
                // Update UI for Azure login
                if (azureLoginSection) {
                    if (azureConfig.clientId && azureConfig.tenantId && azureConfig.redirectUri) {
                        azureLoginSection.style.display = 'block';
                        if (azureLoginButton) azureLoginButton.disabled = false;
                        console.log('Azure AD login enabled with config:', {
                            clientId: azureConfig.clientId,
                            tenantId: azureConfig.tenantId,
                            redirectUri: azureConfig.redirectUri
                        });
                    } else {
                        console.warn('Azure AD is enabled but configuration is incomplete:', publicAuthConfig);
                        azureLoginSection.innerHTML = '<p>Azure AD login is enabled but not fully configured.</p>';
                        azureLoginSection.style.display = 'block';
                    }
                }
            } else {
                console.log("Azure AD auth is disabled via backend config.");
                if (azureLoginSection) azureLoginSection.style.display = 'none';
            }
            
            if (statusEl) {
                statusEl.textContent = 'Configuration loaded successfully';
                setTimeout(() => { 
                    if (statusEl.textContent === 'Configuration loaded successfully') 
                        statusEl.textContent = ''; 
                }, 2000);
            }
            
        } catch (error) {
            console.error('Error fetching auth config:', error);
            if (statusEl) statusEl.textContent = `Failed to load auth configuration: ${error.message}`;
            if (azureLoginSection) azureLoginSection.style.display = 'none';
        }

        // --- Setup global login handlers --- 
        window.handleAzureLogin = async function() {
            if (!azureConfig.clientId || !azureConfig.tenantId) {
                 alert("Azure AD is not configured correctly.");
                 return;
            }
            try {
                // Use the globally defined azureAuthHandler instance (which now has updated config)
                await azureAuthHandler.login(); 
            } catch (error) {
                console.error('Login failed:', error);
                alert(`Login failed: ${error.message}`);
            }
        };

        // --- Handle potential Azure callback --- 
        const urlParams = new URLSearchParams(window.location.search);
        const initialCode = urlParams.get('code');
        const initialState = urlParams.get('state');
        const error = urlParams.get('error');
        const errorDescription = urlParams.get('error_description');

        console.log("Checking for Azure AD callback parameters:", {
            hasCode: !!initialCode,
            hasState: !!initialState,
            error,
            errorDescription,
            currentConfig: {
                clientId: azureConfig.clientId,
                tenantId: azureConfig.tenantId,
                redirectUri: azureConfig.redirectUri,
                authority: azureConfig.authority,
                scope: azureConfig.scope
            }
        });

        if (error) {
            console.error(`Azure AD Callback Error: ${error} - ${errorDescription}`);
            updateStatus(`Azure AD login failed: ${errorDescription || error}`, 'error');
        } else if (initialCode && initialState) {
            // Only handle callback if Azure AD is enabled according to public config
            if (publicAuthConfig?.azure_auth_enabled && azureConfig.clientId && azureConfig.tenantId) {
                console.log("Processing Azure AD callback with config:", {
                    clientId: azureConfig.clientId,
                    tenantId: azureConfig.tenantId,
                    redirectUri: azureConfig.redirectUri,
                    authority: azureConfig.authority
                });
                
                if (statusEl) statusEl.textContent = 'Processing Azure AD login...';
                if (azureLoginButton) azureLoginButton.disabled = true;
                if (credentialLoginButton) credentialLoginButton.disabled = true;
                
                try {
                    // Process callback - handler uses updated azureConfig
                    await azureAuthHandler.handleCallback(initialCode, initialState);
                } catch (error) {
                    console.error("Error during Azure AD callback processing:", error);
                    if (statusEl) statusEl.textContent = `Azure AD login failed: ${error.message}`;
                    // Re-enable buttons on error
                    if (azureLoginButton) azureLoginButton.disabled = false;
                    if (credentialLoginButton) credentialLoginButton.disabled = false;
                }
            } else {
                console.warn("Callback detected but Azure AD is not properly configured:", {
                    enabled: publicAuthConfig?.azure_auth_enabled,
                    hasClientId: !!azureConfig.clientId,
                    hasTenantId: !!azureConfig.tenantId,
                    config: azureConfig
                });
                updateStatus("Login callback ignored; Azure AD not properly configured.", "error");
            }
        } else {
            // Not in a callback state, enable buttons if needed
            console.log("Not in callback mode.");
            if (credentialLoginButton) credentialLoginButton.disabled = false;
            // Azure button enablement is handled above based on publicAuthConfig
        }

    } catch (error) {
        console.error('Initialization failed:', error);
        if (statusEl) {
            statusEl.textContent = `Failed to initialize: ${error.message}. Please check console.`;
        }
        // Ensure buttons are usable if init fails
        if (credentialLoginButton) credentialLoginButton.disabled = false; 
        if (azureLoginButton) azureLoginButton.disabled = false; // Consider context
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

// Function to check token status - KEPT FOR NOW, BUT NOT CALLED ON LOAD
function checkTokenStatus() {
    console.log('Checking token status...');
    
    // Check Azure AD tokens
    const azureTokenStatusEl = document.getElementById('azure-token-status');
    const loginButton = document.querySelector('.azure-login-button');
    const azureAccessToken = localStorage.getItem("azure_access_token");
    const azureIdToken = localStorage.getItem("azure_id_token");
    const azureRefreshToken = localStorage.getItem("azure_refresh_token");
    const azureTokenExpiresAt = localStorage.getItem("azure_token_expires_at");
    
    // Check TimeTagger token first
    const ttTokenStatusEl = document.getElementById('tt-token-status');
    let ttToken = null;
    try {
        if (window.tools && typeof window.tools.get_auth_info === 'function') {
            ttToken = window.tools.get_auth_info();
            console.log('TimeTagger token:', ttToken ? 'Present' : 'Missing');
            if (ttToken) {
                console.log('Token details:', ttToken);
                ttTokenStatusEl.textContent = '✓ TimeTagger Authenticated';
                ttTokenStatusEl.className = 'token-status authenticated';
                // If we have a valid TimeTagger token, redirect to app
                window.location.href = '/timetagger/app/';
                return; // Exit early as we're redirecting
            }
        }
    } catch (error) {
        console.error('Error getting TimeTagger token:', error);
    }
    
    // If we're still here, TimeTagger is not authenticated
    if (ttTokenStatusEl) {
        ttTokenStatusEl.textContent = '✗ TimeTagger Not authenticated';
        ttTokenStatusEl.className = 'token-status not-authenticated';
    }
    
    // If we have a code in the URL, we're in the callback process
    const isCallback = window.location.search.includes('code=');
    
    if (isCallback) {
        azureTokenStatusEl.textContent = '⏳ Processing Azure AD login...';
        azureTokenStatusEl.className = 'token-status processing';
        if (loginButton) loginButton.disabled = true;
        return;
    }
    
    // Check Azure AD token status
    if (azureAccessToken && azureIdToken) {
        // Check if tokens are expired
        let tokenStatus = '✓ Azure AD Authenticated';
        let tokensValid = true;
        
        if (azureTokenExpiresAt) {
            const expiresAt = parseInt(azureTokenExpiresAt, 10);
            const now = Date.now();
            if (expiresAt < now) {
                tokenStatus += ' (Tokens expired)';
                tokensValid = false;
            } else {
                const minutesRemaining = Math.floor((expiresAt - now) / (1000 * 60));
                tokenStatus += ` (Expires in ${minutesRemaining} minutes)`;
            }
        }
        
        azureTokenStatusEl.textContent = tokenStatus;
        azureTokenStatusEl.className = tokensValid ? 'token-status authenticated' : 'token-status not-authenticated';
        
        // Only disable the button if both Azure AD and TimeTagger are authenticated
        if (loginButton) {
            loginButton.disabled = false;
            loginButton.title = tokensValid ? 'Click to complete TimeTagger authentication' : 'Click to login with Azure AD';
        }
    } else {
        azureTokenStatusEl.textContent = '✗ Azure AD Not authenticated';
        azureTokenStatusEl.className = 'token-status not-authenticated';
        if (loginButton) {
            loginButton.disabled = false;
            loginButton.title = 'Click to login with Azure AD';
        }
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

// Add local login handler
async function handleLocalLogin() {
    try {
        const username = document.getElementById('local-username').value.trim();
        const password = document.getElementById('local-password').value.trim();
        
        if (!username || !password) {
            const statusEl = document.getElementById('status');
            if (statusEl) statusEl.textContent = 'Please enter both username and password';
            return;
        }
        
        // Base64 encode the auth info for local login
        const authInfo = {
            method: 'usernamepassword',
            username: username,
            password: password
        };
        const authInfoStr = JSON.stringify(authInfo);
        const authInfoBase64 = btoa(authInfoStr);
        
        console.log('Sending local authentication request');
        
        // Send authentication request
        const response = await fetch('/timetagger/api/v2/bootstrap_authentication', {
            method: 'POST',
            body: authInfoBase64
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            console.error(`Local authentication failed: ${errorText}`);
            const statusEl = document.getElementById('status');
            if (statusEl) statusEl.textContent = 'Local authentication failed: Invalid credentials';
            return;
        }
        
        const data = await response.json();
        
        if (data && data.token) {
            console.log('Local authentication successful');
            
            // Store the token using tools.js
            if (typeof window.tools?.set_auth_info_from_token === 'function') {
                window.tools.set_auth_info_from_token(data.token);
                console.log('Token stored successfully');
                
                // Redirect to app
                window.location.href = '/timetagger/app/';
            } else {
                console.error('tools.set_auth_info_from_token not available');
                const statusEl = document.getElementById('status');
                if (statusEl) statusEl.textContent = 'Error storing authentication token';
            }
        }
    } catch (error) {
        console.error('Local login failed:', error);
        const statusEl = document.getElementById('status');
        if (statusEl) statusEl.textContent = `Local login failed: ${error.message}`;
    }
}

// Function to toggle local login form visibility
function toggleLocalLoginForm() {
    const form = document.getElementById('local-login-form');
    if (form.style.display === 'none' || !form.style.display) {
        form.style.display = 'block';
    } else {
        form.style.display = 'none';
    }
}

// Handle logout message
function showLogoutMessage() {
    const urlParams = new URLSearchParams(window.location.search);
    const message = urlParams.get('message');
    
    if (message === 'logged_out') {
        const messageDiv = document.createElement('div');
        messageDiv.className = 'status-message success';
        messageDiv.innerHTML = '<i class="fas fa-check-circle"></i> You have been successfully logged out.';
        
        // Insert at the top of the content
        const content = document.querySelector('#main-content');
        content.insertBefore(messageDiv, content.firstChild);
        
        // Remove the message parameter from URL
        const newUrl = window.location.pathname;
        window.history.replaceState({}, document.title, newUrl);
        
        // Fade out the message after 5 seconds
        setTimeout(() => {
            messageDiv.style.opacity = '0';
            setTimeout(() => messageDiv.remove(), 1000);
        }, 5000);
    }
}

// Call this when the page loads
window.addEventListener('load', showLogoutMessage);

// Ensure tools.js is loaded or provide a placeholder if needed
window.tools = window.tools || {
    set_auth_info_from_token: function(token) {
        localStorage.setItem('timetagger_auth_token', token);
        console.log("Auth token stored in localStorage (placeholder).");
    }
};

// Helper function to update status messages
function updateStatus(message, type = 'info') {
    const statusEl = document.getElementById('login-status');
    statusEl.style.color = type === 'error' ? 'red' : type === 'success' ? 'green' : 'black';
    statusEl.textContent = message;
    
    // Validate tokens after status update
    validateTokens();
}

// --- Credential Login Handler ---
async function handleCredentialLogin(event) {
    event.preventDefault();
    
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    
    if (!username || !password) {
        updateStatus('Please enter both username and password', 'error');
        return;
    }
    
    const loginData = {
        method: 'usernamepassword',
        username: username,
        password: password
    };
    
    try {
        const response = await fetch('/timetagger/api/v2/bootstrap_authentication', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(loginData)
        });
        
        if (!response.ok) {
            throw new Error(`Login failed: ${response.statusText}`);
        }
        
        const data = await response.json();
        localStorage.setItem('timetagger_auth_token', data.token);
        localStorage.setItem('timetagger_auth_info', JSON.stringify({
            method: 'usernamepassword',
            username: username
        }));
        
        updateStatus('Successfully logged in', 'success');
        validateTokens(); // Validate tokens after successful login
        setTimeout(() => {
            window.location.href = '/timetagger/app';
        }, 1000);
    } catch (error) {
        console.error('Login error:', error);
        updateStatus(`Login failed: ${error.message}`, 'error');
        validateTokens(); // Validate tokens even after error
    }
}

// Add token validation function
async function validateTokens() {
    const tokenStatusDiv = document.getElementById('token-status');
    const azureStatusPre = document.getElementById('azure-token-status');
    const timetaggerStatusPre = document.getElementById('timetagger-token-status');
    
    tokenStatusDiv.style.display = 'block';
    
    // Check Azure AD tokens
    let azureStatus = [];
    try {
        const azureIdToken = localStorage.getItem('azure_id_token');
        const azureAccessToken = localStorage.getItem('azure_access_token');
        
        if (azureIdToken) {
            try {
                const [, payload] = azureIdToken.split('.');
                const decodedPayload = JSON.parse(atob(payload));
                azureStatus.push('ID Token:');
                azureStatus.push(`- Username: ${decodedPayload.preferred_username || 'N/A'}`);
                azureStatus.push(`- Name: ${decodedPayload.name || 'N/A'}`);
                azureStatus.push(`- Expires: ${new Date(decodedPayload.exp * 1000).toLocaleString()}`);
                azureStatus.push(`- Valid: ${Date.now() < decodedPayload.exp * 1000 ? 'Yes' : 'No (Expired)'}`);
            } catch (e) {
                azureStatus.push(`Error parsing ID Token: ${e.message}`);
            }
        } else {
            azureStatus.push('ID Token: Not found');
        }
        
        azureStatus.push('\nAccess Token:');
        if (azureAccessToken) {
            try {
                const [, payload] = azureAccessToken.split('.');
                const decodedPayload = JSON.parse(atob(payload));
                azureStatus.push('- Present: Yes');
                azureStatus.push(`- Expires: ${new Date(decodedPayload.exp * 1000).toLocaleString()}`);
                azureStatus.push(`- Valid: ${Date.now() < decodedPayload.exp * 1000 ? 'Yes' : 'No (Expired)'}`);
            } catch (e) {
                azureStatus.push(`Error parsing Access Token: ${e.message}`);
            }
        } else {
            azureStatus.push('- Not found');
        }
    } catch (e) {
        azureStatus.push(`Error checking Azure tokens: ${e.message}`);
    }
    azureStatusPre.textContent = azureStatus.join('\n');
    
    // Check TimeTagger token
    let ttStatus = [];
    try {
        const ttToken = localStorage.getItem('timetagger_auth_token');
        const ttAuthInfo = localStorage.getItem('timetagger_auth_info');
        
        if (ttToken) {
            try {
                const [, payload] = ttToken.split('.');
                const decodedPayload = JSON.parse(atob(payload));
                ttStatus.push('Token:');
                ttStatus.push(`- Username: ${decodedPayload.username || 'N/A'}`);
                ttStatus.push(`- Admin: ${decodedPayload.is_admin ? 'Yes' : 'No'}`);
                ttStatus.push(`- Expires: ${new Date(decodedPayload.exp * 1000).toLocaleString()}`);
                ttStatus.push(`- Valid: ${Date.now() < decodedPayload.exp * 1000 ? 'Yes' : 'No (Expired)'}`);
            } catch (e) {
                ttStatus.push(`Error parsing Token: ${e.message}`);
            }
        } else {
            ttStatus.push('Token: Not found');
        }
        
        ttStatus.push('\nAuth Info:');
        if (ttAuthInfo) {
            try {
                const authInfo = JSON.parse(ttAuthInfo);
                ttStatus.push(`- Method: ${authInfo.method || 'N/A'}`);
                ttStatus.push(`- Username: ${authInfo.username || 'N/A'}`);
            } catch (e) {
                ttStatus.push(`Error parsing Auth Info: ${e.message}`);
            }
        } else {
            ttStatus.push('- Not found');
        }
    } catch (e) {
        ttStatus.push(`Error checking TimeTagger token: ${e.message}`);
    }
    timetaggerStatusPre.textContent = ttStatus.join('\n');
}

// Add to the script section
window.addEventListener('load', async () => {
    console.log('Page loaded, validating tokens...');
    await validateTokens();
    
    // Check URL for callback parameters
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');
    const state = urlParams.get('state');
    
    if (code && state) {
        console.log('Found callback parameters, handling Azure AD callback...');
        try {
            // Get Azure config
            const response = await fetch('/timetagger/api/v2/public_auth_config');
            if (!response.ok) {
                throw new Error('Failed to get Azure AD configuration');
            }
            const config = await response.json();
            
            // Initialize Azure auth handler
            const azureAuth = new AzureAuthHandler({
                clientId: config.azure_client_id,
                tenantId: config.azure_tenant_id,
                redirectUri: config.azure_redirect_uri,
                clientSecret: config.azure_client_secret,
                authority: config.azure_instance || 'https://login.microsoftonline.com/' + config.azure_tenant_id,
                scope: 'openid profile email'
            });
            
            // Handle the callback
            await azureAuth.handleCallback(code, state);
        } catch (error) {
            console.error('Error handling Azure AD callback:', error);
            updateStatus('Failed to handle Azure AD callback: ' + error.message, 'error');
        }
    }
});

</script>

<div id="debug-container" style="display: none;">
    <div id="debug-output"></div>
</div>

<style>
#debug-container {
    margin-top: 20px;
    padding: 10px;
    background: #f5f5f5;
    border-radius: 4px;
}

#debug-output {
    max-height: 200px;
    overflow-y: auto;
    font-family: monospace;
    font-size: 12px;
    white-space: pre-wrap;
}

.debug-entry {
    padding: 2px 5px;
    border-bottom: 1px solid #ddd;
}

.debug-entry.error {
    color: #d13438;
    background: #fff3f3;
}

.debug-entry.success {
    color: #107c10;
    background: #e6f7e6;
}

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

.login-buttons {
    display: flex;
    flex-direction: column;
    gap: 10px;
    margin-top: 20px;
}

.azure-login-button {
    background-color: #0078d4;
}

.local-login-button {
    background-color: #107c10;
}

.local-login-button:hover:not(:disabled) {
    background-color: #0b5a0b;
}

.local-login-button:active:not(:disabled) {
    background-color: #094509;
}

.local-login-form {
    margin-top: 20px;
    padding: 20px;
    background: #f9f9f9;
    border-radius: 4px;
    border: 1px solid #ddd;
    display: flex;
    flex-direction: column;
    gap: 10px;
}

.local-login-form input {
    padding: 10px;
    border: 1px solid #ddd;
    border-radius: 4px;
    font-size: 14px;
}

.local-login-form input:focus {
    border-color: #107c10;
    outline: none;
}

.local-login-submit {
    background-color: #107c10;
    color: white;
    border: none;
    padding: 10px;
    border-radius: 4px;
    cursor: pointer;
    font-size: 14px;
    margin-top: 10px;
}

.local-login-submit:hover:not(:disabled) {
    background-color: #0b5a0b;
}

.local-login-submit:active:not(:disabled) {
    background-color: #094509;
}

.status-message {
    margin: 1em 0;
    padding: 1em;
    border-radius: 4px;
    text-align: center;
    transition: opacity 1s;
}

.status-message.success {
    background-color: #e8f5e9;
    color: #2e7d32;
    border: 1px solid #c8e6c9;
}

.status-message i {
    margin-right: 0.5em;
}

.token-status {
    margin: 20px 0;
    padding: 15px;
    border: 1px solid #ddd;
    border-radius: 4px;
    background-color: #f9f9f9;
}

.token-status h3 {
    margin: 0 0 15px 0;
    color: #333;
}

.token-section {
    margin-bottom: 15px;
}

.token-section h4 {
    margin: 0 0 10px 0;
    color: #666;
}

.token-section pre {
    margin: 0;
    padding: 10px;
    background-color: #fff;
    border: 1px solid #eee;
    border-radius: 3px;
    white-space: pre-wrap;
    word-wrap: break-word;
    font-family: monospace;
    font-size: 12px;
    line-height: 1.4;
}
</style>

