% Configure External Authentication (Azure AD)
% Set up your Microsoft Azure Active Directory integration.

<div id="config-form" style="padding: 2em; border: 1px solid #ccc; border-radius: 5px; max-width: 600px; margin: 2em auto;">
    <h2>Azure AD Configuration</h2>
    <p>Enter the details for your Azure AD application registration.</p>
    <p id="save-status" style="color: green; font-weight: bold;"></p>

    <div style="margin-bottom: 1.5em; padding-bottom: 1em; border-bottom: 1px solid #eee;">
        <label>
            <input type="checkbox" id="azure-auth-enabled" name="azure-auth-enabled" onchange="toggleAzureFields()">
            Enable Azure AD Authentication
        </label>
    </div>

    <div id="azure-fields-container">
        <div style="margin-bottom: 1em;">
            <label for="azure-client-id">Client ID:</label><br>
            <input type="text" id="azure-client-id" name="azure-client-id" style="width: 95%; padding: 8px; margin-bottom: 10px;">
        </div>

        <div style="margin-bottom: 1em;">
            <label for="azure-tenant-id">Tenant ID:</label><br>
            <input type="text" id="azure-tenant-id" name="azure-tenant-id" style="width: 95%; padding: 8px; margin-bottom: 10px;">
        </div>

        <div style="margin-bottom: 1em;">
            <label for="azure-client-secret">Client Secret:</label><br>
            <input type="password" id="azure-client-secret" name="azure-client-secret" style="width: 95%; padding: 8px; margin-bottom: 10px;">
            <small>Note: This secret is stored securely on the server.</small>
        </div>
        
        <div style="margin-bottom: 1em;">
             <label for="azure-redirect-uri">Redirect URI:</label><br>
             <input type="text" id="azure-redirect-uri" name="azure-redirect-uri" style="width: 95%; padding: 8px; margin-bottom: 10px;">
             <small>This should match the Redirect URI configured in Azure AD (usually `http://your-domain/timetagger/auth/callback` or `http://localhost:8000/timetagger/auth/callback`).</small>
         </div>
    </div>

    <button id="save-button" onclick="saveAzureConfig()" style="padding: 10px 15px;">Save Configuration</button>
    <button id="test-button" onclick="testAzureConfig()" style="padding: 10px 15px; margin-left: 10px; background-color: #4CAF50; color: white;">Test Configuration</button>
</div>

<script>
// Get auth token from localStorage
function getAuthToken() {
    return localStorage.getItem('timetagger_auth_token');
}

function toggleAzureFields() {
    const isEnabled = document.getElementById('azure-auth-enabled').checked;
    const fieldsContainer = document.getElementById('azure-fields-container');
    const inputs = fieldsContainer.querySelectorAll('input[type="text"], input[type="password"]');
    
    fieldsContainer.style.opacity = isEnabled ? '1' : '0.5';
    inputs.forEach(input => {
        if (input.id !== 'azure-redirect-uri') { // Keep redirect URI always visible but controlled by enabled state
             input.disabled = !isEnabled;
        }
    });
}

async function loadAzureConfig() {
    console.log("Loading Azure config from backend...");
    const statusElement = document.getElementById('save-status');
    statusElement.textContent = 'Loading configuration...';
    statusElement.style.color = '#666';

    try {
        const authToken = getAuthToken();
        if (!authToken) {
            throw new Error('No authentication token found. Please log in again.');
        }

        // Decode the JWT token to check admin status
        const tokenParts = authToken.split('.');
        const payload = JSON.parse(atob(tokenParts[1]));
        if (!payload.is_admin) {
            throw new Error('Only admin users can access this configuration page.');
        }

        const response = await fetch('/api/v2/app_config', {
            headers: {
                'authtoken': authToken
            }
        });

        if (!response.ok) {
            throw new Error(`HTTP error ${response.status}: ${await response.text()}`);
        }
        
        const config = await response.json();
        
        const clientId = config.azure_client_id || '';
        const tenantId = config.azure_tenant_id || '';
        const clientSecret = config.azure_client_secret || '';
        const isEnabled = config.azure_auth_enabled === true;
        const redirectUri = config.azure_redirect_uri || `${window.location.origin}/timetagger/auth/callback`;

        document.getElementById('azure-auth-enabled').checked = isEnabled;
        document.getElementById('azure-client-id').value = clientId;
        document.getElementById('azure-tenant-id').value = tenantId;
        document.getElementById('azure-client-secret').value = clientSecret;
        document.getElementById('azure-redirect-uri').value = redirectUri;

        console.log("Loaded from backend - Enabled:", isEnabled, "ClientID:", clientId ? '***' : 'Empty', "TenantID:", tenantId ? '***' : 'Empty', "Secret:", clientSecret ? '***' : 'Empty');
        
        toggleAzureFields();
        statusElement.textContent = 'Configuration loaded.';
        statusElement.style.color = 'green';
        setTimeout(() => { statusElement.textContent = ''; }, 3000);

    } catch (error) {
        console.error("Error loading Azure config:", error);
        statusElement.textContent = `Error loading configuration: ${error.message}`;
        statusElement.style.color = 'red';
        toggleAzureFields();
        
        // If not admin, disable all fields and buttons
        if (error.message.includes('Only admin users')) {
            document.getElementById('azure-auth-enabled').disabled = true;
            document.getElementById('save-button').disabled = true;
            document.getElementById('test-button').disabled = true;
            const fieldsContainer = document.getElementById('azure-fields-container');
            fieldsContainer.style.opacity = '0.5';
            fieldsContainer.querySelectorAll('input').forEach(input => {
                input.disabled = true;
            });
        }
    }
}

async function saveAzureConfig() {
    console.log("Saving Azure config to backend...");
    const statusElement = document.getElementById('save-status');
    statusElement.textContent = 'Saving configuration...';
    statusElement.style.color = '#666';

    try {
        const authToken = getAuthToken();
        if (!authToken) {
            throw new Error('No authentication token found. Please log in again.');
        }

        // Decode the JWT token to check admin status
        const tokenParts = authToken.split('.');
        const payload = JSON.parse(atob(tokenParts[1]));
        if (!payload.is_admin) {
            throw new Error('Only admin users can save this configuration.');
        }

        const isEnabled = document.getElementById('azure-auth-enabled').checked;
        const clientId = document.getElementById('azure-client-id').value.trim();
        const tenantId = document.getElementById('azure-tenant-id').value.trim();
        const clientSecret = document.getElementById('azure-client-secret').value.trim();
        const redirectUri = document.getElementById('azure-redirect-uri').value.trim();

        if (!redirectUri) {
            statusElement.textContent = 'Redirect URI is required.';
            statusElement.style.color = 'red';
            return;
        }

        const configData = {
            key: 'auth_config',
            value: {
                azure_auth_enabled: isEnabled,
                azure_client_id: clientId,
                azure_tenant_id: tenantId,
                azure_client_secret: clientSecret,
                azure_instance: 'https://login.microsoftonline.com',
                azure_redirect_uri: redirectUri
            }
        };

        console.log('Sending config:', JSON.stringify(configData, (key, value) => 
            key === 'azure_client_secret' ? '***' : value));

        statusElement.textContent = 'Saving configuration...';
        statusElement.style.color = '#666';

        const response = await fetch('/api/v2/app_config', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'authtoken': authToken
            },
            body: JSON.stringify(configData)
        });

        console.log('Response status:', response.status);
        console.log('Response headers:', Object.fromEntries(response.headers.entries()));
        
        const responseText = await response.text();
        console.log('Raw response:', responseText);

        if (!response.ok) {
            throw new Error(`HTTP error ${response.status}: ${responseText}`);
        }
        
        const result = JSON.parse(responseText);
        console.log("Save successful:", result);

        statusElement.textContent = '✓ Configuration saved successfully!';
        statusElement.style.color = 'green';
        setTimeout(() => { 
            if (statusElement.style.color === 'green') {
                statusElement.textContent = '';
            }
        }, 3000);

    } catch (error) {
        console.error("Error saving Azure config:", error);
        let errorMessage = error.message;
        if (errorMessage.includes('Invalid content type')) {
            errorMessage = 'Server error: Invalid request format';
        }
        statusElement.textContent = `❌ Error: ${errorMessage}`;
        statusElement.style.color = 'red';
    }
}

async function testAzureConfig() {
    console.log("Testing Azure AD configuration...");
    const statusElement = document.getElementById('save-status');
    statusElement.textContent = 'Testing Azure AD configuration...';
    statusElement.style.color = '#666';

    try {
        const authToken = getAuthToken();
        if (!authToken) {
            throw new Error('No authentication token found. Please log in again.');
        }

        // Decode the JWT token to check admin status
        const tokenParts = authToken.split('.');
        const payload = JSON.parse(atob(tokenParts[1]));
        if (!payload.is_admin) {
            throw new Error('Only admin users can test this configuration.');
        }

        const clientId = document.getElementById('azure-client-id').value.trim();
        const tenantId = document.getElementById('azure-tenant-id').value.trim();
        const clientSecret = document.getElementById('azure-client-secret').value.trim();
        const redirectUri = document.getElementById('azure-redirect-uri').value.trim();
        
        if (!clientId || !tenantId || !clientSecret || !redirectUri) {
            statusElement.textContent = 'Please fill in all Azure AD credentials before testing.';
            statusElement.style.color = 'red';
            return;
        }

        const configData = {
            azure_client_id: clientId,
            azure_tenant_id: tenantId,
            azure_client_secret: clientSecret,
            azure_instance: 'https://login.microsoftonline.com',
            azure_redirect_uri: redirectUri
        };

        console.log('Sending test request:', JSON.stringify(configData, (key, value) => 
            key === 'azure_client_secret' ? '***' : value));

        statusElement.textContent = 'Connecting to Azure AD...';
        statusElement.style.color = '#666';

        const response = await fetch('/api/v2/test_azure_config', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'authtoken': authToken
            },
            body: JSON.stringify(configData)
        });

        console.log('Response status:', response.status);
        console.log('Response headers:', Object.fromEntries(response.headers.entries()));
        
        const responseText = await response.text();
        console.log('Raw response:', responseText);

        if (!response.ok) {
            throw new Error(`HTTP error ${response.status}: ${responseText}`);
        }
        
        const result = JSON.parse(responseText);
        console.log("Test result:", result);
        
        if (result.success) {
            statusElement.textContent = '✓ Azure AD configuration test successful!';
            statusElement.style.color = 'green';
        } else {
            let errorMessage = result.error || 'Unknown error';
            // Extract the main error message if it's an Azure AD error
            if (errorMessage.includes('Azure AD error:')) {
                const match = errorMessage.match(/Azure AD error: ([^.]+)/);
                if (match) {
                    errorMessage = match[1];
                }
            }
            statusElement.textContent = `❌ Test failed: ${errorMessage}`;
            statusElement.style.color = 'red';
        }

    } catch (error) {
        console.error("Error testing Azure config:", error);
        statusElement.textContent = `❌ Error: ${error.message}`;
        statusElement.style.color = 'red';
    }

    // Don't clear the status automatically for errors
    if (statusElement.style.color === 'green') {
        setTimeout(() => { 
            if (statusElement.style.color === 'green') {
                statusElement.textContent = '';
            }
        }, 5000);
    }
}

// Load config when the page loads
window.addEventListener('load', loadAzureConfig);
</script> 