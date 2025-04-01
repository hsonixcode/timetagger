% TimeTagger - Account
% User account

# Account

<!--account_start-->

<script src='./app/tools.js'></script>

<script>

function nav_to(url) {
    location.href = url;
}

async function refresh_auth_status() {
    let el = document.getElementById('authstatus');
    let logoutallbutton = document.getElementById('logoutallbutton');

    el.innerHTML = "Getting auth status ...";
    await tools.sleepms(200);

    let auth = tools.get_auth_info();
    console.log("Auth info:", auth);

    if (auth) {
        let html = "Logged in as <b>" + auth.username + "</b>";
        
        // Check if logged in via Azure AD
        const azureIdToken = localStorage.getItem("azure_id_token");
        const azureAccessToken = localStorage.getItem("azure_access_token");
        
        if (azureIdToken) {
            html += "<br><span class='token-status'>Azure AD Status:</span>";
            try {
                // Decode Azure ID token
                const idTokenParts = azureIdToken.split('.');
                if (idTokenParts.length !== 3) {
                    throw new Error('Invalid Azure ID token format');
                }
                
                let base64Payload = idTokenParts[1];
                base64Payload = base64Payload.replace(/-/g, '+').replace(/_/g, '/');
                while (base64Payload.length % 4) {
                    base64Payload += '=';
                }
                
                const decodedPayload = atob(base64Payload);
                const azurePayload = JSON.parse(decodedPayload);
                console.log("Azure token payload:", azurePayload);
                
                // Display Azure token information
                if (azurePayload.exp) {
                    const expiresDate = new Date(azurePayload.exp * 1000);
                    html += "<br>✓ Azure token valid until: " + expiresDate.toLocaleString();
                }
                if (azurePayload.name) {
                    html += "<br>✓ Name: " + azurePayload.name;
                }
                if (azurePayload.preferred_username) {
                    html += "<br>✓ Email: " + azurePayload.preferred_username;
                }
                if (azurePayload.oid) {
                    html += "<br>✓ Azure Object ID: " + azurePayload.oid;
                }
            } catch (error) {
                console.error('Error parsing Azure token:', error);
                html += "<br>✓ Azure AD authenticated (token details unavailable)";
                html += "<br>✗ Error: " + error.message;
            }
        }
        
        // Display TimeTagger token information
        try {
            // Decode the JWT token to get expiration
            const tokenParts = auth.token.split('.');
            if (tokenParts.length !== 3) {
                throw new Error('Invalid token format');
            }
            
            // Base64 decode and parse the payload
            let base64Payload = tokenParts[1];
            // Add padding if needed
            base64Payload = base64Payload.replace(/-/g, '+').replace(/_/g, '/');
            while (base64Payload.length % 4) {
                base64Payload += '=';
            }
            
            const decodedPayload = atob(base64Payload);
            const tokenPayload = JSON.parse(decodedPayload);
            console.log("TimeTagger token payload:", tokenPayload);
            
            html += "<br><span class='token-status'>TimeTagger Token Status:</span>";
            
            // Display all token fields
            for (const [key, value] of Object.entries(tokenPayload)) {
                if (key === 'expires') {
                    const expiresDate = new Date(value * 1000);
                    html += "<br>✓ Valid until: " + expiresDate.toLocaleString();
                } else if (key === 'is_admin') {
                    html += "<br>✓ Admin status: " + (value ? "Yes" : "No");
                } else {
                    html += "<br>✓ " + key + ": " + value;
                }
            }
        } catch (error) {
            console.error('Error parsing token:', error);
            html += "<br><span class='token-status'>TimeTagger Token Status:</span>";
            html += "<br>✓ Valid (token details unavailable)";
            html += "<br>✗ Error: " + error.message;
            
            // Raw token for debugging
            if (auth.token) {
                html += "<br>Raw token: " + auth.token.substring(0, 20) + "...";
            }
        }
        
        el.innerHTML = html;
        logoutallbutton.disabled = false;
    } else {
        el.innerHTML = "Not logged in.";
        logoutallbutton.disabled = true;
    }
}

async function refresh_api_token(reset) {
    let el = document.getElementById('apitoken');
    let resetapikeybutton = document.getElementById('resetapikey');
    let auth = tools.get_auth_info();

    el.innerHTML = "Getting API token ...";
    await tools.sleepms(200);

    if (auth) {
        let url = tools.build_api_url("apitoken");
        if (reset) { url += "?reset=1"; }
        let init = {method: "GET", headers:{authtoken: auth.token}};
        try {
            let res = await fetch(url, init);
            if (res.status != 200) {
                el.innerText = "Fail: " + await res.text();
                console.error("API token fetch failed:", await res.text());
                return;
            }
            
            let responseText = await res.text();
            console.log("API token response:", responseText);
            
            // Handle token - API returns plain token string, not JSON
            let tokenValue = responseText.trim();
            
            // Check if somehow it's a JSON response (for backward compatibility)
            if (tokenValue.startsWith('{') && tokenValue.endsWith('}')) {
                try {
                    let d = JSON.parse(tokenValue);
                    tokenValue = d.token || tokenValue;
                } catch (jsonError) {
                    console.warn("Response looks like JSON but couldn't be parsed:", jsonError);
                    // Continue with the raw token
                }
            }
            
            // Detailed token display
            let htmlContent = "<span class='token-status'>API Token Status:</span><br>✓ Active<br>";
            
            // Try to decode and display token details
            try {
                const tokenParts = tokenValue.split('.');
                if (tokenParts.length === 3) {
                    let base64Payload = tokenParts[1];
                    base64Payload = base64Payload.replace(/-/g, '+').replace(/_/g, '/');
                    while (base64Payload.length % 4) {
                        base64Payload += '=';
                    }
                    
                    const decodedPayload = atob(base64Payload);
                    const tokenPayload = JSON.parse(decodedPayload);
                    console.log("API token payload:", tokenPayload);
                    
                    // Show token details
                    for (const [key, value] of Object.entries(tokenPayload)) {
                        if (key === 'expires') {
                            const expiresDate = new Date(value * 1000);
                            htmlContent += "✓ Valid until: " + expiresDate.toLocaleString() + "<br>";
                        } else if (key === 'is_admin') {
                            htmlContent += "✓ Admin privileges: " + (value ? "Yes" : "No") + "<br>";
                        } else {
                            htmlContent += "✓ " + key + ": " + value + "<br>";
                        }
                    }
                }
            } catch (error) {
                console.error("Error decoding API token:", error);
                htmlContent += "✓ Token valid (details unavailable)<br>";
            }
            
            // Always show the token string
            htmlContent += "Token: " + tokenValue;
            el.innerHTML = htmlContent;
            resetapikeybutton.disabled = false;
            
        } catch (error) {
            console.error("API token fetch error:", error);
            el.innerHTML = "<span class='token-status'>API Token Status:</span><br>✗ Error fetching token: " + error.message;
            resetapikeybutton.disabled = true;
        }
    } else {
        el.innerHTML = "<span class='token-status'>API Token Status:</span><br>✗ Not available (not logged in)";
        resetapikeybutton.disabled = true;
    }
}

async function reset_webtoken_seed() {
    let el = document.getElementById('logoutallbutton');
    el.innerHTML = "Resetting web token seed ...";
    await tools.renew_webtoken(true, true);
    await tools.sleepms(1000);
    el.innerHTML = "Done!";
    await tools.sleepms(1000);
    el.innerHTML = "Logout all other devices";
}

async function reset_api_key() {
    await refresh_api_token(true);
}

async function copy_api_key() {
    let el = document.getElementById('apitoken');
    let but = document.getElementById('copyapikey');
    tools.copy_dom_node(el)
    but.innerHTML = "<i class='fas'></i>";
    await tools.sleepms(1000)
    but.innerHTML = "<i class='fas'></i>";
}

var refresh_functions = [refresh_auth_status, refresh_api_token];
function refresh() {
    for (let func of refresh_functions) {
        func();
    }
}
window.addEventListener("load", refresh);
</script>

<style>
#apitoken {
    overflow-wrap: anywhere;
    margin-left: 5px;
    font-size:80%;
}

.token-status {
    font-weight: bold;
    color: #333;
    margin-top: 10px;
    display: block;
}
</style>

<br />

<button onclick='window.refresh()' style='float: right;' class='whitebutton'><i class='fas'>\uf2f1</i> Refresh</button>

## Authentication status

<div id='authstatus'>Getting auth status ...</div>

<button class='whitebutton' onclick='nav_to("./login#page=./account");'>Log in</button>
<button class='whitebutton' onclick='nav_to("./logout#page=./account");'>Log out</button>
<button class='whitebutton' id='logoutallbutton' disbaled onclick='reset_webtoken_seed();'>Logout all other devices</button>

<details style='font-size: 80%; padding:0.5em; border: 1px solid #ddd; border-radius:4px;'>
    <summary style='user-select:none;'>web-token details</summary>
    <p>
    Authentication occurs using a web-token that is obtained when logging in.
    The token is valid for 14 days, and is refreshed when you use the application.
    It is recommended to log out on devices that you do not own. In case you forget,
    or when a device is lost/stolen, the token seed can be reset, causing all other sessions to log out.
    </p>
</details>
<br />

## API token

<div id='apitoken' class='monospace'>Getting API token ...</div>

<button type='button' class='whitebutton' id='resetapikey' onclick='reset_api_key();'>Reset API token</button>
<button type='button' class='whitebutton' id='copyapikey' onclick='copy_api_key();'><i class='fas'></i></button>

<details style='font-size: 80%; padding:0.5em; border: 1px solid #ddd; border-radius:4px;'>
    <summary style='user-select:none;'>api-token details</summary>
    <p>
    The API token enables access to the server for 3d party applications (e.g. the CLI tool). API tokens do not expire.
    Reset the token to revoke access for all applications using the current API token.
    </p>
</details>
<br />

<!--account_end-->
