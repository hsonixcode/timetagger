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
        <button id="login-button" onclick="handleCredentialLogin()" style="padding: 10px 15px;">Login</button>
    </div>

    <div id="azure-login" style="margin-top: 1em; border-top: 1px solid #ccc; padding-top: 1em;">
        <p>Or login with:</p>
        <button id="azure-login-button" onclick="handleAzureLogin()" style="padding: 10px 15px;">Azure Active Directory</button> 
        <!-- Note: The handleAzureLogin function needs to be defined globally or attached correctly -->
    </div>
</div>

<script>
// Set Azure AD configuration variables
window.AZURE_CLIENT_ID = '{{ timetagger_azure_client_id }}';
window.AZURE_TENANT_ID = '{{ timetagger_azure_tenant_id }}';
window.AZURE_REDIRECT_URI = '{{ timetagger_azure_redirect_uri }}';
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
        return `openid profile email ${this.clientId}/.default`;
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
            this.updateStatus('Azure AD login failed: ' + error.message, 'error');
            throw error;
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
            console.log('No original page found, redirecting to app page');
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
                
                // Store the token using tools.js
                if (typeof window.tools?.set_auth_info_from_token === 'function') {
                    window.tools.set_auth_info_from_token(data.token);
                    console.log('Token stored successfully');
                    
                    // Update status and redirect
                    this.updateStatus('Authentication successful, redirecting...', 'success');
                    
                    // Short delay to ensure token is stored and status is shown
                    setTimeout(() => {
                        window.location.href = '/timetagger/app/';
                    }, 500);
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

// Initialize Azure AD auth handler
const azureAuth = new AzureAuthHandler(azureConfig);

// Log URL immediately on script start, before 'load' event
console.log("[EARLY LOG] Initial window.location.href:", window.location.href);

// --- Immediate check for callback mode ---
const urlParams = new URLSearchParams(window.location.search);
const initialCode = urlParams.get('code');
const initialState = urlParams.get('state');
const isInCallbackMode = !!initialCode && !!initialState;

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
        
        // Define scripts to load with relative paths
        const scripts = [
             './app/tools.js',
             './app/utils.js',
             './app/dt.js',
             './app/stores.js',
             './app/dialogs.js',
             './app/front.js'
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
    const statusElement = document.getElementById('login-status');
    if (statusElement) {
        statusElement.textContent = message;
        statusElement.style.color = type === 'error' ? 'red' : 'green';
    }
    console.log(`Status (${type}): ${message}`);
}

// --- Credential Login Handler ---
async function handleCredentialLogin() {
    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');
    const username = usernameInput.value.trim();
    const password = passwordInput.value.trim(); // NOTE: Sending password in clear text, handled by bcrypt on server

    if (!username || !password) {
        updateStatus('Username and password are required.', 'error');
        return;
    }

    updateStatus('Logging in...');

    try {
        // Base64 encode the auth info
        const authInfo = {
            method: 'usernamepassword',
            username: username,
            password: password
        };
        const authInfoStr = JSON.stringify(authInfo);
        const authInfoBase64 = btoa(authInfoStr); // Standard Base64 encoding

        console.log('Sending username/password authentication request');

        // Send authentication request
        const response = await fetch('/timetagger/api/v2/bootstrap_authentication', {
            method: 'POST',
            body: authInfoBase64
        });

        if (!response.ok) {
            const errorText = await response.text() || `HTTP error ${response.status}`;
            console.error(`Credential login failed: ${errorText}`);
            updateStatus(`Login failed: ${errorText}`, 'error');
            return;
        }

        const data = await response.json();

        if (data && data.token) {
            console.log('Credential login successful, token received');
            window.tools.set_auth_info_from_token(data.token); // Store the token
            updateStatus('Login successful! Redirecting...', 'success');

            // Redirect to the main app page
            window.location.href = '/timetagger/app/';

        } else {
            console.error('Credential login failed: No token received.');
            updateStatus('Login failed: Server did not return a token.', 'error');
        }

    } catch (error) {
        console.error('Error during credential login:', error);
        updateStatus('Login failed: An unexpected error occurred.', 'error');
    }
}

// --- Azure AD Handling (Initialization and Callback) ---
const azureAuthHandler = new AzureAuthHandler(azureConfig);

// Check for Azure AD callback parameters
window.addEventListener('load', () => {
    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');
    const state = params.get('state');
    const error = params.get('error');
    const errorDescription = params.get('error_description');

    if (error) {
        console.error(`Azure AD Error: ${error} - ${errorDescription}`);
        updateStatus(`Azure AD login failed: ${errorDescription || error}`, 'error');
    } else if (code && state) {
        // Handle the callback if code and state are present
        updateStatus('Processing Azure AD login...');
        azureAuthHandler.handleCallback(code, state);
    } else {
        console.log("No Azure AD callback detected, showing login form.");
        // Optionally hide/show login sections based on config availability
        const azureLoginButton = document.getElementById('azure-login-button');
        const azureLoginSection = document.getElementById('azure-login');
        if (!azureConfig.clientId || !azureConfig.tenantId) {
            if (azureLoginButton) azureLoginButton.style.display = 'none';
            if (azureLoginSection) azureLoginSection.innerHTML = '<p>Azure AD login is not configured.</p>';
            console.log("Azure AD config missing, hiding Azure login option.");
        }
    }
    
    // Add event listener for Enter key in password field
    const passwordInput = document.getElementById('password');
    if (passwordInput) {
        passwordInput.addEventListener('keypress', function(event) {
            if (event.key === 'Enter') {
                event.preventDefault(); // Prevent default form submission
                handleCredentialLogin();
            }
        });
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
</style>

