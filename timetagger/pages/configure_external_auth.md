% Configure External Authentication (Azure AD)
% Set up your Microsoft Azure Active Directory integration.

<div id="config-form" style="padding: 2em; border: 1px solid #ccc; border-radius: 5px; max-width: 600px; margin: 2em auto;">
    <h2>Azure AD Configuration</h2>
    <p>Enter the details for your Azure AD application registration.</p>
    <p id="save-status" style="color: green; font-weight: bold;"></p>

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
        <small>Note: This secret is currently stored in your browser's local storage. For production, consider a more secure server-side storage method.</small>
    </div>
    
    <div style="margin-bottom: 1em;">
         <label for="azure-redirect-uri">Redirect URI:</label><br>
         <input type="text" id="azure-redirect-uri" name="azure-redirect-uri" style="width: 95%; padding: 8px; margin-bottom: 10px;" readonly>
         <small>This should match the Redirect URI configured in Azure AD (usually `http://your-domain/timetagger/auth/callback` or `http://localhost:8000/timetagger/auth/callback`).</small>
     </div>


    <button id="save-button" onclick="saveAzureConfig()" style="padding: 10px 15px;">Save Configuration</button>
    <button id="clear-button" onclick="clearAzureConfig()" style="padding: 10px 15px; margin-left: 10px; background-color: #f44336; color: white;">Clear Configuration</button>
</div>

<script>
function loadAzureConfig() {
    console.log("Loading Azure config from localStorage...");
    const clientId = localStorage.getItem('timetagger_azure_client_id') || '';
    const tenantId = localStorage.getItem('timetagger_azure_tenant_id') || '';
    const clientSecret = localStorage.getItem('timetagger_azure_client_secret') || ''; // Load secret
    const redirectUri = `${window.location.origin}/timetagger/auth/callback`; // Construct based on current location


    document.getElementById('azure-client-id').value = clientId;
    document.getElementById('azure-tenant-id').value = tenantId;
    document.getElementById('azure-client-secret').value = clientSecret; // Set secret field
    document.getElementById('azure-redirect-uri').value = redirectUri;

    console.log("Loaded - ClientID:", clientId ? '***' : 'Empty', "TenantID:", tenantId ? '***' : 'Empty', "Secret:", clientSecret ? '***' : 'Empty');

}

function saveAzureConfig() {
    console.log("Saving Azure config to localStorage...");
    const clientId = document.getElementById('azure-client-id').value.trim();
    const tenantId = document.getElementById('azure-tenant-id').value.trim();
    const clientSecret = document.getElementById('azure-client-secret').value.trim(); // Get secret
    const redirectUri = document.getElementById('azure-redirect-uri').value.trim(); // Get redirect URI (though it's readonly now)


    localStorage.setItem('timetagger_azure_client_id', clientId);
    localStorage.setItem('timetagger_azure_tenant_id', tenantId);
    localStorage.setItem('timetagger_azure_client_secret', clientSecret); // Save secret
    // Redirect URI is determined dynamically, but we could save it if needed:
    // localStorage.setItem('timetagger_azure_redirect_uri', redirectUri); 


    console.log("Saved - ClientID:", clientId ? '***' : 'Empty', "TenantID:", tenantId ? '***' : 'Empty', "Secret:", clientSecret ? '***' : 'Empty');

    
    const statusElement = document.getElementById('save-status');
    statusElement.textContent = 'Configuration saved successfully!';
    setTimeout(() => { statusElement.textContent = ''; }, 3000); // Clear message after 3 seconds
    
    // Optionally, update window variables if the main app uses them directly
     window.AZURE_CLIENT_ID = clientId;
     window.AZURE_TENANT_ID = tenantId;
     window.AZURE_CLIENT_SECRET = clientSecret;
     window.AZURE_REDIRECT_URI = redirectUri;

}

function clearAzureConfig() {
     console.log("Clearing Azure config from localStorage...");
     if (confirm("Are you sure you want to clear the Azure AD configuration?")) {
         localStorage.removeItem('timetagger_azure_client_id');
         localStorage.removeItem('timetagger_azure_tenant_id');
         localStorage.removeItem('timetagger_azure_client_secret');
         // localStorage.removeItem('timetagger_azure_redirect_uri');
         
         // Clear input fields
         document.getElementById('azure-client-id').value = '';
         document.getElementById('azure-tenant-id').value = '';
         document.getElementById('azure-client-secret').value = '';
         
         const statusElement = document.getElementById('save-status');
         statusElement.textContent = 'Configuration cleared!';
          setTimeout(() => { statusElement.textContent = ''; }, 3000);
          
         // Clear window variables
          window.AZURE_CLIENT_ID = '';
          window.AZURE_TENANT_ID = '';
          window.AZURE_CLIENT_SECRET = '';
          // Keep redirect URI as it's based on current host
     }
 }


// Load existing config when the page loads
window.addEventListener('load', loadAzureConfig);
</script> 