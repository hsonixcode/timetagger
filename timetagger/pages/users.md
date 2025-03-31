% Users
% Manage users in TimeTagger

<div id="users-panel" style="padding: 2em; background-color: #f9f9f9; border-radius: 8px; max-width: 1200px; margin: 2em auto; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
    <h2 style="margin-top: 0; color: #333; font-size: 24px;">User Management</h2>
    <p id="status" style="color: #28a745; font-weight: bold; min-height: 24px;"></p>

    <div style="margin-bottom: 1.5em; display: flex; align-items: center; flex-wrap: wrap; gap: 10px;">
        <input type="text" id="search-input" placeholder="Search users..." style="padding: 10px; width: 300px; border: 1px solid #ddd; border-radius: 4px; flex: 1;">
        <button id="search-button" onclick="searchUsers()" style="padding: 10px 16px; background-color: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer;">Search</button>
        <button id="clear-button" onclick="clearSearch()" style="padding: 10px 16px; background-color: #6c757d; color: white; border: none; border-radius: 4px; cursor: pointer;">Clear</button>
    </div>

    <div id="users-section" style="margin-bottom: 2em; background-color: white; padding: 1.5em; border-radius: 6px; box-shadow: 0 1px 3px rgba(0,0,0,0.08);">
        <h3 style="margin-top: 0; color: #333; font-size: 18px; border-bottom: 2px solid #f0f0f0; padding-bottom: 10px;">All Users</h3>
        <div id="all-users-list" style="margin-top: 1em;">
            Loading users...
        </div>
    </div>

    <div id="admin-links" style="margin-top: 2em; background-color: white; padding: 1.5em; border-radius: 6px; box-shadow: 0 1px 3px rgba(0,0,0,0.08);">
        <h3 style="margin-top: 0; color: #333; font-size: 18px; border-bottom: 2px solid #f0f0f0; padding-bottom: 10px;">Administration</h3>
        <ul style="padding-left: 20px; margin-top: 15px;">
            <li style="margin-bottom: 8px;"><a href="/timetagger/admin" style="color: #007bff; text-decoration: none;">Admin Dashboard</a></li>
            <li style="margin-bottom: 8px;"><a href="/timetagger/configure_external_auth" style="color: #007bff; text-decoration: none;">Configure Azure AD Authentication</a></li>
            <li style="margin-bottom: 8px;"><button id="backfill-button" onclick="runBackfill()" style="background: none; border: none; color: #007bff; text-decoration: none; cursor: pointer; padding: 0; font: inherit; text-align: left;">Run Login Database Backfill</button></li>
            <li style="margin-bottom: 8px;"><button id="debug-button" onclick="toggleDebugInfo()" style="background: none; border: none; color: #007bff; text-decoration: none; cursor: pointer; padding: 0; font: inherit; text-align: left;">Toggle Debug Information</button></li>
            <li style="margin-bottom: 8px;"><button id="test-azure-button" onclick="testAzureLogin()" style="background: none; border: none; color: #007bff; text-decoration: none; cursor: pointer; padding: 0; font: inherit; text-align: left;">Test Azure User Recording</button></li>
            <li style="margin-bottom: 8px;"><button id="debug-azure-users" class="list-group-item list-group-item-action" onclick="debugAzureUsers()" style="background: none; border: none; color: #007bff; text-decoration: none; cursor: pointer; padding: 0; font: inherit; text-align: left;">Debug Azure Users in Database</button></li>
        </ul>
        <p id="backfill-status" style="margin-top: 10px; font-style: italic; color: #6c757d;"></p>
        <p id="test-status" style="margin-top: 10px; font-style: italic; color: #6c757d;"></p>
    </div>
    
    <!-- Debug Information Panel -->
    <div id="debug-panel" style="margin-top: 2em; background-color: white; padding: 1.5em; border-radius: 6px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); display: none;">
        <h3 style="margin-top: 0; color: #333; font-size: 18px; border-bottom: 2px solid #f0f0f0; padding-bottom: 10px;">Debug Information</h3>
        <div id="debug-output" style="font-family: monospace; white-space: pre-wrap; background-color: #f8f9fa; padding: 15px; border-radius: 4px; max-height: 400px; overflow-y: auto;">
            Loading debug information...
        </div>
    </div>
</div>

<script>
// Get auth token from localStorage
function getAuthToken() {
    return localStorage.getItem('timetagger_auth_token');
}

// Format date to readable format
function formatDate(timestamp) {
    if (!timestamp || timestamp === 0) {
        return "Never logged in";
    }
    
    const date = new Date(timestamp * 1000);
    const now = new Date();
    const diffMs = now - date;
    
    // If last active was over a day ago
    if (diffMs > 24 * 60 * 60 * 1000) {
        const days = Math.floor(diffMs / (24 * 60 * 60 * 1000));
        
        if (days > 30) {
            const months = Math.floor(days / 30);
            if (months > 12) {
                const years = Math.floor(months / 12);
                return `${years} year${years > 1 ? 's' : ''} ago`;
            }
            return `${months} month${months > 1 ? 's' : ''} ago`;
        }
        
        return `${days} day${days > 1 ? 's' : ''} ago`;
    }
    
    // If last active was within the last 24 hours
    const hours = Math.floor(diffMs / (60 * 60 * 1000));
    if (hours > 0) {
        return `${hours} hour${hours > 1 ? 's' : ''} ago`;
    }
    
    // If last active was within the last hour
    const minutes = Math.floor(diffMs / (60 * 1000));
    if (minutes > 0) {
        return `${minutes} minute${minutes > 1 ? 's' : ''} ago`;
    }
    
    // If last active was within the last minute
    return 'Just now';
}

// Determine if a user has never logged in
function hasNeverLoggedIn(user) {
    // For the centralized login database, we consider a user has never logged in
    // if they don't have a last_login value or if it's 0
    return !user.last_login || user.last_login === 0;
}

// Format metadata as a string for display
function formatMetadata(metadata) {
    if (!metadata || Object.keys(metadata).length === 0) {
        return 'No metadata';
    }
    
    // Format the metadata object as a string with line breaks
    return Object.entries(metadata)
        .map(([key, value]) => {
            // For nested objects or arrays, stringify them
            if (typeof value === 'object' && value !== null) {
                value = JSON.stringify(value);
            }
            return `${key}: ${value}`;
        })
        .join(', ');
}

// Add the loading spinner style to the document
document.addEventListener('DOMContentLoaded', function() {
    // Add CSS for access status
    const style = document.createElement('style');
    style.textContent = `
        .access-allowed {
            color: #28a745;
            font-weight: bold;
            display: flex;
            align-items: center;
            gap: 5px;
        }
        .access-denied {
            color: #dc3545;
            font-weight: bold;
            display: flex;
            align-items: center;
            gap: 5px;
        }
        .empty-state {
            text-align: center;
            padding: 30px;
            color: #6c757d;
        }
        .empty-state i {
            font-size: 36px;
            margin-bottom: 15px;
            opacity: 0.5;
        }
        .empty-state p {
            margin: 0;
            font-size: 16px;
        }
        .loading-spinner {
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 30px;
        }
        .spinner {
            width: 40px;
            height: 40px;
            border: 4px solid rgba(0, 123, 255, 0.1);
            border-radius: 50%;
            border-top: 4px solid #007bff;
            animation: spin 1s linear infinite;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .user-list-widget {
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            overflow: hidden;
            background-color: #fff;
            max-width: 100%;
            display: flex;
            flex-direction: column;
            height: 400px; /* Fixed height for scrolling */
        }
        .user-list-header {
            display: grid;
            grid-template-columns: 3fr 3fr 2fr 2fr 2fr;
            gap: 10px;
            padding: 12px 15px;
            background-color: #f8f9fa;
            border-bottom: 2px solid #e0e0e0;
            font-weight: bold;
            position: sticky;
            top: 0;
            z-index: 10;
        }
        .user-list-body {
            flex: 1;
            overflow-y: auto;
            scrollbar-width: thin;
            scrollbar-color: #d1d1d1 #f1f1f1;
        }
        .user-list-body::-webkit-scrollbar {
            width: 8px;
        }
        .user-list-body::-webkit-scrollbar-track {
            background: #f1f1f1;
            border-radius: 4px;
        }
        .user-list-body::-webkit-scrollbar-thumb {
            background-color: #d1d1d1;
            border-radius: 4px;
        }
        .user-list-item {
            display: grid;
            grid-template-columns: 3fr 3fr 2fr 2fr 2fr;
            gap: 10px;
            padding: 12px 15px;
            border-bottom: 1px solid #f0f0f0;
            align-items: center;
            transition: background-color 0.2s ease;
        }
        .user-list-item:hover {
            background-color: #f8f9fa;
            cursor: pointer;
        }
        .user-list-item.selected {
            background-color: #e6f2ff;
            border-left: 3px solid #007bff;
        }
        .user-list-name {
            font-weight: 500;
        }
        .access-select {
            padding: 6px 10px;
            border-radius: 4px;
            border: 1px solid #ced4da;
            font-size: 14px;
            width: 100%;
            cursor: pointer;
            background-color: #f8f9fa;
            transition: all 0.2s ease;
        }
        .access-select.allowed {
            border-color: #28a745;
            background-color: rgba(40, 167, 69, 0.1);
        }
        .access-select.denied {
            border-color: #dc3545;
            background-color: rgba(220, 53, 69, 0.1);
        }
        .access-select:focus {
            outline: none;
            box-shadow: 0 0 0 2px rgba(0, 123, 255, 0.25);
        }
        /* User details panel */
        .user-detail-panel {
            background-color: white;
            border-radius: 8px;
            border: 1px solid #e0e0e0;
            padding: 20px;
            margin-top: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            display: none;
        }
        .user-detail-panel.visible {
            display: block;
        }
        .user-detail-header {
            display: flex;
            align-items: center;
            margin-bottom: 15px;
            border-bottom: 1px solid #f0f0f0;
            padding-bottom: 10px;
        }
        .user-detail-name {
            font-size: 18px;
            font-weight: bold;
            margin: 0;
        }
        .user-detail-role {
            margin-left: 10px;
            padding: 3px 8px;
            background-color: #e9ecef;
            border-radius: 12px;
            font-size: 12px;
            color: #495057;
        }
        .user-detail-info {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
        }
        .detail-item {
            margin-bottom: 10px;
        }
        .detail-label {
            font-weight: 500;
            color: #6c757d;
            margin-bottom: 5px;
            font-size: 14px;
        }
        .detail-value {
            font-size: 15px;
        }
        .user-actions {
            margin-top: 20px;
            display: flex;
            gap: 10px;
        }
        .action-button {
            padding: 8px 16px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-weight: 500;
            transition: background-color 0.2s;
        }
        .action-button.primary {
            background-color: #007bff;
            color: white;
        }
        .action-button.danger {
            background-color: #dc3545;
            color: white;
        }
        .action-button.neutral {
            background-color: #6c757d;
            color: white;
        }
        .action-button:hover {
            opacity: 0.9;
        }
        /* Responsive design */
        @media (max-width: 768px) {
            .user-list-header, .user-list-item {
                grid-template-columns: 3fr 3fr 2fr;
            }
            .user-list-header > div:nth-child(4),
            .user-list-header > div:nth-child(5),
            .user-list-item > div:nth-child(4),
            .user-list-item > div:nth-child(5) {
                display: none;
            }
            .user-detail-info {
                grid-template-columns: 1fr;
            }
        }
    `;
    document.head.appendChild(style);
    
    // Load users when the page loads
    loadUsers();
});

// Function to handle loading users
async function loadUsers() {
    const statusElement = document.getElementById('debug-status');
    if (statusElement) {
        statusElement.textContent = 'Loading users...';
        statusElement.style.color = '#6c757d';
    }
    
    const authToken = getAuthToken();
    
    // Initialize debug info
    const debugInfo = {
        newApiResponse: { status: 'not called', data: null },
        oldApiResponse: { status: 'not called', data: null },
        azureUserCount: 0,
        localUserCount: 0,
        finalUserCount: 0
    };
    
    try {
        // First try to get users from the new API
        try {
            const response = await fetch('/api/v2/login-users', {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'authtoken': authToken
                }
            });
            
            debugInfo.newApiResponse.status = response.status;
            
            if (response.ok) {
                const data = await response.json();
                debugInfo.newApiResponse.data = data;
                
                // Format the users for display
                const formattedUsers = [];
                
                // Process the login users
                if (data.login_users && Array.isArray(data.login_users)) {
                    // Count Azure and local users
                    const azureUsers = data.login_users.filter(user => user.user_type === 'azure');
                    const localUsers = data.login_users.filter(user => user.user_type === 'local');
                    
                    debugInfo.azureUserCount = azureUsers.length;
                    debugInfo.localUserCount = localUsers.length;
                    
                    // Add each user with proper formatting
                    data.login_users.forEach(user => {
                        formattedUsers.push({
                            username: user.username,
                            email: user.email,
                            role: user.role || 'user',
                            allowed: user.access === 'allowed',
                            userType: user.user_type,
                            lastLogin: formatDateTime(user.last_login)
                        });
                    });
                }
                
                debugInfo.finalUserCount = formattedUsers.length;
                
                // Update the users table
                createUsersTable(formattedUsers);
                
                if (statusElement) {
                    statusElement.textContent = `Loaded ${formattedUsers.length} users from central database.`;
                    statusElement.style.color = '#28a745';
                }
                
                // Update debug info display
                updateDebugInfo();
                
                return;
            } else {
                debugInfo.newApiResponse.error = await response.text();
                console.error('Error loading login users:', debugInfo.newApiResponse.error);
            }
        } catch (error) {
            debugInfo.newApiResponse.error = error.message;
            console.error('Error calling /api/v2/login-users:', error);
        }
        
        // If we get here, we need to try the old API
        console.log('Falling back to legacy users API');
        
        try {
            const response = await fetch('/api/v2/users', {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'authtoken': authToken
                }
            });
            
            debugInfo.oldApiResponse.status = response.status;
            
            if (response.ok) {
                const data = await response.json();
                debugInfo.oldApiResponse.data = data;
                console.log('Users data received:', data);
                
                // Count users
                debugInfo.azureUserCount = data.azure_users ? data.azure_users.length : 0;
                debugInfo.localUserCount = data.local_users ? data.local_users.length : 0;
                
                // Format users from the old API
                const formattedUsers = [];
                
                // Add local users
                if (data.local_users && Array.isArray(data.local_users)) {
                    data.local_users.forEach(user => {
                        formattedUsers.push({
                            username: user.username,
                            email: user.email || user.username,
                            role: user.role || 'user',
                            allowed: user.is_allowed !== false,
                            userType: 'local',
                            lastLogin: formatDateTime(user.last_active)
                        });
                    });
                }
                
                // Add Azure users
                if (data.azure_users && Array.isArray(data.azure_users)) {
                    data.azure_users.forEach(user => {
                        formattedUsers.push({
                            username: user.username,
                            email: user.email || user.username,
                            role: user.role || 'user',
                            allowed: user.is_allowed !== false,
                            userType: 'azure',
                            lastLogin: formatDateTime(user.last_active)
                        });
                    });
                }
                
                debugInfo.finalUserCount = formattedUsers.length;
                
                // Update the users table
                createUsersTable(formattedUsers);
                
                if (statusElement) {
                    statusElement.textContent = `Loaded ${formattedUsers.length} users from legacy API.`;
                    statusElement.style.color = '#28a745';
                }
            } else {
                debugInfo.oldApiResponse.error = await response.text();
                console.error('Error loading users from legacy API:', debugInfo.oldApiResponse.error);
                
                if (statusElement) {
                    statusElement.textContent = 'Failed to load users. Check console for details.';
                    statusElement.style.color = '#dc3545';
                }
            }
        } catch (error) {
            debugInfo.oldApiResponse.error = error.message;
            console.error('Error calling /api/v2/users:', error);
            
            if (statusElement) {
                statusElement.textContent = `Error: ${error.message}`;
                statusElement.style.color = '#dc3545';
            }
        }
        
        // Update debug info
        updateDebugInfo();
        
    } catch (error) {
        console.error('Error in loadUsers:', error);
        
        if (statusElement) {
            statusElement.textContent = `Error: ${error.message}`;
            statusElement.style.color = '#dc3545';
        }
    }
}

// Create a table for the users
function createUsersTable(users) {
    const tableContainer = document.getElementById('users-table-container');
    
    // Ensure users is always an array
    users = users || [];
    
    if (!users || users.length === 0) {
        tableContainer.innerHTML = '<p>No users found.</p>';
        return;
    }
    
    try {
        // Count Azure users
        const azureUsers = users.filter(user => user && user.userType === 'azure');
        const localUsers = users.filter(user => user && user.userType === 'local');
        
        // Create the header with user counts
        const headerText = `All Users (${users.length} total: ${localUsers.length} local, ${azureUsers.length} Azure)`;
        const header = document.createElement('h3');
        header.textContent = headerText;
        
        // Create table
        const table = document.createElement('table');
        table.className = 'table table-striped';
        
        // Create table header
        const thead = document.createElement('thead');
        const headerRow = document.createElement('tr');
        
        const headers = ['Username', 'Email', 'Role', 'User Type', 'Status', 'Last Activity', 'Actions'];
        headers.forEach(headerText => {
            const th = document.createElement('th');
            th.textContent = headerText;
            headerRow.appendChild(th);
        });
        
        thead.appendChild(headerRow);
        table.appendChild(thead);
        
        // Create table body
        const tbody = document.createElement('tbody');
        
        users.forEach(user => {
            if (!user) return; // Skip null/undefined users
            
            const row = document.createElement('tr');
            
            // Highlight Azure users with a subtle background
            if (user.userType === 'azure') {
                row.style.backgroundColor = '#f0f8ff'; // Light blue background
            }
            
            // Username
            const usernameCell = document.createElement('td');
            usernameCell.textContent = user.username || '';
            row.appendChild(usernameCell);
            
            // Email
            const emailCell = document.createElement('td');
            emailCell.textContent = user.email || '';
            row.appendChild(emailCell);
            
            // Role
            const roleCell = document.createElement('td');
            const roleBadge = document.createElement('span');
            roleBadge.textContent = user.role || 'user';
            roleBadge.className = 'badge ' + ((user.role || '') === 'admin' ? 'badge-primary' : 'badge-secondary');
            roleBadge.style.padding = '0.4em 0.6em';
            roleCell.appendChild(roleBadge);
            row.appendChild(roleCell);
            
            // User Type
            const typeCell = document.createElement('td');
            const typeBadge = document.createElement('span');
            typeBadge.textContent = user.userType || 'local';
            typeBadge.className = 'badge ' + ((user.userType || '') === 'azure' ? 'badge-info' : 'badge-secondary');
            typeBadge.style.padding = '0.4em 0.6em';
            typeCell.appendChild(typeBadge);
            row.appendChild(typeCell);
            
            // Status
            const statusCell = document.createElement('td');
            const statusBadge = document.createElement('span');
            statusBadge.textContent = user.allowed ? 'Allowed' : 'Not Allowed';
            statusBadge.className = 'badge ' + (user.allowed ? 'badge-success' : 'badge-danger');
            statusBadge.style.padding = '0.4em 0.6em';
            statusCell.appendChild(statusBadge);
            row.appendChild(statusCell);
            
            // Last Activity
            const lastLoginCell = document.createElement('td');
            lastLoginCell.textContent = user.lastLogin || 'Never';
            row.appendChild(lastLoginCell);
            
            // Actions
            const actionsCell = document.createElement('td');
            
            // Toggle access button
            const toggleButton = document.createElement('button');
            toggleButton.className = 'btn btn-sm ' + (user.allowed ? 'btn-outline-danger' : 'btn-outline-success');
            toggleButton.textContent = user.allowed ? 'Disable Access' : 'Enable Access';
            toggleButton.onclick = () => toggleUserAccess(user.username, !user.allowed);
            actionsCell.appendChild(toggleButton);
            
            row.appendChild(actionsCell);
            
            tbody.appendChild(row);
        });
        
        table.appendChild(tbody);
        
        // Clear the container and add the new table
        tableContainer.innerHTML = '';
        tableContainer.appendChild(header);
        tableContainer.appendChild(table);
    } catch (error) {
        console.error('Error creating users table:', error);
        tableContainer.innerHTML = `<p>Error creating users table: ${error.message}</p>`;
    }
}

// Format a timestamp
function formatDateTime(timestamp) {
    if (!timestamp) return 'Never';
    
    const date = new Date(timestamp * 1000);
    return date.toLocaleString();
}

// Update debug information display
function updateDebugInfo() {
    try {
        const debugElement = document.getElementById('debug-info');
        if (debugElement) {
            try {
                debugElement.textContent = JSON.stringify(debugInfo || {}, null, 2);
            } catch (e) {
                debugElement.textContent = "Error stringifying debug info: " + e.message;
            }
        }
        
        // Also update the debug content if it exists
        const debugContent = document.getElementById('debug-content');
        if (debugContent) {
            let html = '<h4>API Debug Information</h4>';
            
            // New API response
            html += '<h5>Login Users API Response</h5>';
            html += `<p>Status: ${(debugInfo && debugInfo.newApiResponse) ? debugInfo.newApiResponse.status : 'unknown'}</p>`;
            if (debugInfo && debugInfo.newApiResponse && debugInfo.newApiResponse.error) {
                html += `<p>Error: ${debugInfo.newApiResponse.error}</p>`;
            }
            
            // Old API response
            html += '<h5>Legacy Users API Response</h5>';
            html += `<p>Status: ${(debugInfo && debugInfo.oldApiResponse) ? debugInfo.oldApiResponse.status : 'unknown'}</p>`;
            if (debugInfo && debugInfo.oldApiResponse && debugInfo.oldApiResponse.error) {
                html += `<p>Error: ${debugInfo.oldApiResponse.error}</p>`;
            }
            
            // User counts
            html += '<h5>User Counts</h5>';
            html += `<p>Azure Users: ${debugInfo ? debugInfo.azureUserCount || 0 : 0}</p>`;
            html += `<p>Local Users: ${debugInfo ? debugInfo.localUserCount || 0 : 0}</p>`;
            html += `<p>Total Users: ${debugInfo ? debugInfo.finalUserCount || 0 : 0}</p>`;
            
            // Add fetch debug data
            html += '<button onclick="fetchDebugData()" class="btn btn-sm btn-secondary mt-3">Fetch More Debug Data</button>';
            html += '<div id="additional-debug-data" class="mt-3"></div>';
            
            debugContent.innerHTML = html;
        }
    } catch (error) {
        console.error('Error updating debug info:', error);
    }
}

// Run the backfill operation to populate the central login database
async function runBackfill() {
    const statusElement = document.getElementById('backfill-status');
    const backfillButton = document.getElementById('backfill-button');
    
    // Disable the button during operation
    backfillButton.disabled = true;
    statusElement.textContent = 'Backfilling login database...';
    statusElement.style.color = '#6c757d';
    
    try {
        const authToken = getAuthToken();
        if (!authToken) {
            throw new Error('No authentication token found. Please log in again.');
        }
        
        // Call the backfill endpoint
        let response;
        try {
            response = await fetch('/api/login-users/backfill', {
                method: 'POST',
                headers: {
                    'authtoken': authToken
                }
            });
        } catch (error) {
            console.log('First fetch attempt failed, trying with timetagger prefix');
            response = await fetch('/timetagger/api/login-users/backfill', {
                method: 'POST',
                headers: {
                    'authtoken': authToken
                }
            });
        }
        
        if (!response.ok) {
            throw new Error(`HTTP error ${response.status}: ${await response.text()}`);
        }
        
        const data = await response.json();
        console.log('Backfill result:', data);
        
        // Show success message with detailed information
        statusElement.textContent = `Backfill completed successfully. Processed ${data.details.success_count + data.details.error_count} users (${data.details.success_count} succeeded, ${data.details.error_count} failed).`;
        statusElement.style.color = '#28a745';
        
        // Wait a moment before reloading users to ensure database updates are complete
        setTimeout(async () => {
            // Try to fetch from the new API endpoint to verify it's working
            let verifyResponse;
            try {
                verifyResponse = await fetch('/api/login-users', {
                    headers: {
                        'authtoken': authToken
                    }
                });
                
                if (verifyResponse.ok) {
                    const verifyData = await verifyResponse.json();
                    const userCount = (verifyData.login_users || []).length;
                    
                    if (userCount > 0) {
                        statusElement.textContent += ` Central database now contains ${userCount} users.`;
                    } else {
                        statusElement.textContent += " Central database appears to be empty despite backfill.";
                        statusElement.style.color = '#ffc107'; // Warning color
                    }
                } else {
                    statusElement.textContent += " Unable to verify central database contents.";
                    statusElement.style.color = '#ffc107'; // Warning color
                }
            } catch (error) {
                console.error('Error verifying central database:', error);
            }
            
            // Reload users
            await loadUsers();
        }, 1000);
        
    } catch (error) {
        console.error('Error running backfill:', error);
        statusElement.textContent = `Error: ${error.message}`;
        statusElement.style.color = '#dc3545';
    } finally {
        // Re-enable the button
        backfillButton.disabled = false;
    }
}

// Toggle debug information
function toggleDebugInfo() {
    const debugPanel = document.getElementById('debug-panel');
    if (debugPanel.style.display === 'none') {
        debugPanel.style.display = 'block';
        // Refresh debug info when panel is shown
        fetchDebugData();
    } else {
        debugPanel.style.display = 'none';
    }
}

// Fetch additional debug data
async function fetchDebugData() {
    const debugOutput = document.getElementById('debug-output');
    
    if (!debugOutput) return;
    
    debugOutput.textContent = 'Loading debug information...';
    
    try {
        const authToken = getAuthToken();
        if (!authToken) {
            throw new Error('No authentication token found.');
        }
        
        // Try to check login database directly
        const debugData = {
            timestamp: new Date().toISOString(),
            tokensInLocalStorage: {
                auth_token: !!localStorage.getItem('timetagger_auth_token'),
                webtoken_azure: !!localStorage.getItem('timetagger_webtoken_azure'),
                user_info: localStorage.getItem('timetagger_user_info') 
                    ? JSON.parse(localStorage.getItem('timetagger_user_info'))
                    : null
            }
        };
        
        // Update debug panel
        updateDebugInfo();
    } catch (error) {
        console.error('Error fetching debug data:', error);
        debugOutput.textContent = `Error fetching debug data: ${error.message}`;
    }
}

// Add a new function to manually trigger an Azure user login test
async function testAzureLogin() {
    const statusElement = document.getElementById('test-status');
    statusElement.textContent = 'Testing Azure user recording...';
    statusElement.style.color = '#6c757d';
    
    try {
        const authToken = getAuthToken();
        if (!authToken) {
            throw new Error('No authentication token found. Please log in again.');
        }
        
        // First try to get current user info
        const userInfo = localStorage.getItem('timetagger_user_info');
        
        if (!userInfo) {
            throw new Error('No user info found in local storage');
        }
        
        const user = JSON.parse(userInfo);
        
        // Determine if this is an Azure login by checking localStorage
        const isAzureUser = !!localStorage.getItem('timetagger_webtoken_azure');
        
        // Show user info
        const userData = {
            username: user.username || '',
            email: prompt('Enter email address for test Azure user:', user.email || user.username || ''),
            isAzureUser: isAzureUser,
            localStorageTokens: {
                auth_token: !!localStorage.getItem('timetagger_auth_token'),
                webtoken_azure: !!localStorage.getItem('timetagger_webtoken_azure')
            }
        };
        
        if (!userData.email) {
            throw new Error('Email is required');
        }
        
        statusElement.textContent = `Testing with user: ${userData.username} (${userData.email}) - Azure user: ${isAzureUser}`;
        
        // Create both a manual test record and also force a database check
        const user_type = isAzureUser ? 'azure' : 'local';
        
        // Call the manual test endpoint
        const response = await fetch('/api/v2/users/record_login_test', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'authtoken': authToken
            },
            body: JSON.stringify({
                email: userData.email,
                username: userData.username,
                user_type: user_type,
                role: 'user',
                is_allowed: true,
                metadata: {
                    auth_method: isAzureUser ? 'azure' : 'local',
                    test_initiated: true,
                    timestamp: new Date().toISOString(),
                    localStorage: userData.localStorageTokens
                }
            })
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error ${response.status}: ${await response.text()}`);
        }
        
        const data = await response.json();
        console.log('Test login record result:', data);
        
        // Show success message
        statusElement.textContent = `Test login record created successfully for ${userData.username}. User type: ${user_type}`;
        statusElement.style.color = '#28a745';
        
        // Reload users after a short delay
        setTimeout(async () => {
            await loadUsers();
        }, 1000);
        
    } catch (error) {
        console.error('Error testing Azure login:', error);
        statusElement.textContent = `Error: ${error.message}`;
        statusElement.style.color = '#dc3545';
    }
}

// Add a new button for debugging Azure users specifically
async function debugAzureUsers() {
    const debugPanel = document.getElementById('debug-panel');
    const debugContent = document.getElementById('debug-content');
    const statusElement = document.getElementById('test-status');
    statusElement.textContent = 'Checking database for Azure users...';
    statusElement.style.color = '#6c757d';
    
    try {
        const authToken = getAuthToken();
        if (!authToken) {
            throw new Error('No authentication token found. Please log in again.');
        }
        
        // Call the debug endpoint
        const response = await fetch('/api/v2/login-users/debug', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'authtoken': authToken
            }
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error ${response.status}: ${await response.text()}`);
        }
        
        const data = await response.json();
        console.log('Debug Azure users result:', data);
        
        // Format the debug info
        let htmlContent = '<h4>Azure User Debug Information</h4>';
        
        // Database info
        htmlContent += `<h5>Database Information</h5>`;
        htmlContent += `<p>Login DB exists: ${data.debug_info.login_db_exists}</p>`;
        htmlContent += `<p>Login DB path: ${data.debug_info.login_db_path}</p>`;
        
        // Azure users
        htmlContent += `<h5>Azure Users in Login Database (${data.debug_info.azure_users.length})</h5>`;
        if (data.debug_info.azure_users.length > 0) {
            htmlContent += '<ul>';
            data.debug_info.azure_users.forEach(user => {
                htmlContent += `<li><strong>${user.username}</strong> (${user.email}) - Role: ${user.role}, Allowed: ${user.is_allowed}</li>`;
            });
            htmlContent += '</ul>';
        } else {
            htmlContent += '<p>No Azure users found in the login database.</p>';
        }
        
        // Local users
        htmlContent += `<h5>Local Users in Login Database (${data.debug_info.local_users.length})</h5>`;
        if (data.debug_info.local_users.length > 0) {
            htmlContent += '<ul>';
            data.debug_info.local_users.forEach(user => {
                htmlContent += `<li><strong>${user.username}</strong> (${user.email}) - Role: ${user.role}, Allowed: ${user.is_allowed}</li>`;
            });
            htmlContent += '</ul>';
        } else {
            htmlContent += '<p>No local users found in the login database.</p>';
        }
        
        // UserManager data
        htmlContent += `<h5>UserManager Data</h5>`;
        if (data.debug_info.user_manager_data) {
            htmlContent += `<p>Local users: ${data.debug_info.user_manager_data.local_users.length}</p>`;
            htmlContent += `<p>Azure users: ${data.debug_info.user_manager_data.azure_users.length}</p>`;
            
            if (data.debug_info.user_manager_data.azure_users.length > 0) {
                htmlContent += '<h6>Azure Users from UserManager:</h6><ul>';
                data.debug_info.user_manager_data.azure_users.forEach(user => {
                    htmlContent += `<li><strong>${user.username}</strong> - Is allowed: ${user.is_allowed}</li>`;
                });
                htmlContent += '</ul>';
            }
        } else {
            htmlContent += `<p>Error retrieving UserManager data: ${data.debug_info.user_manager_error || 'Unknown error'}</p>`;
        }
        
        // Display in the debug panel
        debugContent.innerHTML = htmlContent;
        debugPanel.style.display = 'block';
        
        // Show success message
        statusElement.textContent = `Azure user debug completed. Found ${data.debug_info.azure_users.length} Azure users in database.`;
        statusElement.style.color = '#28a745';
        
    } catch (error) {
        console.error('Error debugging Azure users:', error);
        statusElement.textContent = `Error: ${error.message}`;
        statusElement.style.color = '#dc3545';
    }
}

// Toggle a user's access
async function toggleUserAccess(username, allow) {
    if (!username) {
        console.error('Username is required to toggle access');
        return;
    }
    
    try {
        const statusElement = document.getElementById('debug-status');
        if (statusElement) {
            statusElement.textContent = `Updating access for ${username}...`;
            statusElement.style.color = '#6c757d';
        }
        
        const authToken = getAuthToken();
        if (!authToken) {
            throw new Error('No authentication token found. Please log in again.');
        }
        
        // Call the API to update user access
        const response = await fetch('/api/v2/users/update_access', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'authtoken': authToken
            },
            body: JSON.stringify({
                username: username,
                is_allowed: allow
            })
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error ${response.status}: ${await response.text()}`);
        }
        
        const data = await response.json();
        
        // Show success message
        if (statusElement) {
            statusElement.textContent = `Successfully ${allow ? 'enabled' : 'disabled'} access for ${username}`;
            statusElement.style.color = '#28a745';
        }
        
        // Reload users after a short delay
        setTimeout(async () => {
            await loadUsers();
        }, 1000);
        
    } catch (error) {
        console.error('Error toggling user access:', error);
        
        const statusElement = document.getElementById('debug-status');
        if (statusElement) {
            statusElement.textContent = `Error: ${error.message}`;
            statusElement.style.color = '#dc3545';
        }
    }
}
</script>