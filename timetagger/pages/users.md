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
        <div id="users-table-container" style="margin-top: 1em;">
            Loading users...
        </div>
    </div>

    <div id="administration" style="margin-top: 2em; background-color: white; padding: 1.5em; border-radius: 6px; box-shadow: 0 1px 3px rgba(0,0,0,0.08);">
        <h3 style="margin-top: 0; color: #333; font-size: 18px; border-bottom: 2px solid #f0f0f0; padding-bottom: 10px;">Administration</h3>
        <ul style="padding-left: 20px; margin-top: 15px;">
            <li style="margin-bottom: 8px;"><a href="/timetagger/admin" style="color: #007bff; text-decoration: none;">Admin Dashboard</a></li>
            <li style="margin-bottom: 8px;"><a href="/timetagger/configure_external_auth" style="color: #007bff; text-decoration: none;">Configure Azure AD Authentication</a></li>
        </ul>
    </div>

    <!-- Debug Information Panel -->
    <div id="debug-panel" style="margin-top: 2em; background-color: white; padding: 1.5em; border-radius: 6px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); display: none;">
        <h3 style="margin-top: 0; color: #333; font-size: 18px; border-bottom: 2px solid #f0f0f0; padding-bottom: 10px;">Debug Information</h3>
        <pre id="debug-info" style="font-family: monospace; white-space: pre-wrap; background-color: #f8f9fa; padding: 15px; border-radius: 4px; max-height: 400px; overflow-y: auto;">Loading debug information...</pre>
        <div id="debug-content" style="margin-top: 20px;">
            <!-- Debug content will be added here -->
        </div>
    </div>
</div>

<script>
// Global variables
let debugInfo = {
    newApiResponse: { status: 'not called', data: null },
    oldApiResponse: { status: 'not called', data: null },
    azureUserCount: 0,
    localUserCount: 0,
    finalUserCount: 0
};

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
                            name: user.name || user.username,
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
                            name: user.name || user.username,
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
                            name: user.name || user.username,
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
        tableContainer.innerHTML = '<div class="empty-state"><p>No users found.</p></div>';
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
        
        // Create a compact style for users list
        const style = document.createElement('style');
        style.textContent = `
            .user-list {
                border: 1px solid #e0e0e0;
                border-radius: 6px;
                overflow: hidden;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                max-height: 600px;
                display: flex;
                flex-direction: column;
            }
            .list-header {
                display: grid;
                grid-template-columns: minmax(200px, 3fr) minmax(200px, 2fr) minmax(180px, 1fr) minmax(100px, 1fr);
                gap: 10px;
                padding: 10px 15px;
                background-color: #f8f9fa;
                border-bottom: 2px solid #dee2e6;
                font-weight: 600;
                color: #495057;
                font-size: 13px;
                position: sticky;
                top: 0;
                z-index: 10;
            }
            .user-items-container {
                overflow-y: auto;
                scrollbar-width: thin;
                scrollbar-color: #d1d1d1 #f8f9fa;
                max-height: 550px;
            }
            .user-items-container::-webkit-scrollbar {
                width: 8px;
            }
            .user-items-container::-webkit-scrollbar-track {
                background: #f8f9fa;
            }
            .user-items-container::-webkit-scrollbar-thumb {
                background-color: #d1d1d1;
                border-radius: 4px;
            }
            .user-item {
                padding: 10px 15px;
                border-bottom: 1px solid #f0f0f0;
                display: grid;
                grid-template-columns: minmax(200px, 3fr) minmax(200px, 2fr) minmax(180px, 1fr) minmax(100px, 1fr);
                gap: 10px;
                align-items: center;
                background-color: #fff;
                transition: background-color 0.2s;
                font-size: 14px;
            }
            .user-item:hover {
                background-color: #f9f9f9;
            }
            .user-item:last-child {
                border-bottom: none;
            }
            .user-info {
                display: flex;
                flex-direction: column;
            }
            .user-name {
                font-weight: 600;
                margin-bottom: 2px;
            }
            .user-email {
                color: #6c757d;
                font-size: 13px;
            }
            .user-controls {
                display: flex;
                align-items: center;
                gap: 16px;
            }
            .control-group {
                display: flex;
                align-items: center;
                gap: 8px;
                white-space: nowrap;
            }
            .control-label {
                font-weight: 500;
                color: #495057;
                font-size: 13px;
            }
            .role-select {
                padding: 4px 8px;
                border-radius: 4px;
                border: 1px solid #ced4da;
                font-size: 13px;
                background-color: #fff;
            }
            .access-badge {
                display: inline-block;
                padding: 2px 8px;
                border-radius: 12px;
                font-size: 12px;
                font-weight: 600;
                color: white;
            }
            .access-badge.allowed {
                background-color: #28a745;
            }
            .access-badge.denied {
                background-color: #dc3545;
            }
            .user-type-badge {
                display: inline-block;
                padding: 2px 8px;
                border-radius: 12px;
                font-size: 12px;
                font-weight: 600;
                color: white;
                margin-left: 6px;
            }
            .user-type-badge.azure {
                background-color: #17a2b8;
            }
            .user-type-badge.local {
                background-color: #6c757d;
            }
            .toggle-switch {
                position: relative;
                display: inline-block;
                width: 36px;
                height: 20px;
            }
            .toggle-switch input {
                opacity: 0;
                width: 0;
                height: 0;
            }
            .toggle-slider {
                position: absolute;
                cursor: pointer;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background-color: #dc3545;
                border-radius: 20px;
                transition: .3s;
            }
            .toggle-slider:before {
                position: absolute;
                content: "";
                height: 16px;
                width: 16px;
                left: 2px;
                bottom: 2px;
                background-color: white;
                border-radius: 50%;
                transition: .3s;
            }
            input:checked + .toggle-slider {
                background-color: #28a745;
            }
            input:disabled + .toggle-slider {
                opacity: 0.6;
                cursor: not-allowed;
            }
            input:checked + .toggle-slider:before {
                transform: translateX(16px);
            }
            .last-activity {
                color: #6c757d;
                font-size: 13px;
                text-align: right;
            }
            .azure-user {
                border-left: 3px solid #17a2b8;
            }
            .disabled-user {
                border-left: 3px solid #dc3545;
                background-color: #fff8f8;
            }
            .disabled-badge {
                background-color: #dc3545;
                color: white;
                font-size: 11px;
                padding: 1px 5px;
                border-radius: 10px;
                margin-left: 6px;
                font-weight: 600;
            }
            @media (max-width: 992px) {
                .user-item, .list-header {
                    grid-template-columns: minmax(200px, 2fr) minmax(180px, 1fr) 100px;
                }
                .last-activity {
                    display: none;
                }
            }
            @media (max-width: 768px) {
                .user-item, .list-header {
                    grid-template-columns: 1fr;
                    gap: 8px;
                }
                .user-controls {
                    margin-top: 8px;
                }
            }
        `;
        document.head.appendChild(style);
        
        // Create user list container
        const userListContainer = document.createElement('div');
        userListContainer.className = 'user-list';
        
        // Add list header
        const listHeader = document.createElement('div');
        listHeader.className = 'list-header';
        
        const userInfoHeader = document.createElement('div');
        userInfoHeader.textContent = 'User';
        
        const controlsHeader = document.createElement('div');
        controlsHeader.textContent = 'Role & Access';
        
        const typeHeader = document.createElement('div');
        typeHeader.textContent = 'Type & Status';
        
        const lastActivityHeader = document.createElement('div');
        lastActivityHeader.textContent = 'Last Activity';
        
        listHeader.appendChild(userInfoHeader);
        listHeader.appendChild(controlsHeader);
        listHeader.appendChild(typeHeader);
        listHeader.appendChild(lastActivityHeader);
        
        userListContainer.appendChild(listHeader);
        
        // Create a scrollable container for user items
        const userItemsContainer = document.createElement('div');
        userItemsContainer.className = 'user-items-container';
        
        // Process each user
        users.forEach(user => {
            if (!user) return; // Skip null/undefined users
            
            // Create user item
            const userItem = document.createElement('div');
            userItem.className = 'user-item';
            userItem.dataset.username = user.username;
            
            // Add appropriate classes for styling
            if (user.userType === 'azure') {
                userItem.classList.add('azure-user');
            }
            
            if (!user.allowed) {
                userItem.classList.add('disabled-user');
            }
            
            // 1. User info column
            const userInfo = document.createElement('div');
            userInfo.className = 'user-info';
            
            const userName = document.createElement('div');
            userName.className = 'user-name';
            userName.textContent = user.name || user.username || '';
            
            // Add access disabled badge if needed
            if (!user.allowed) {
                const disabledBadge = document.createElement('span');
                disabledBadge.className = 'disabled-badge';
                disabledBadge.textContent = 'DISABLED';
                userName.appendChild(disabledBadge);
            }
            
            const userEmail = document.createElement('div');
            userEmail.className = 'user-email';
            userEmail.textContent = user.email || '';
            
            userInfo.appendChild(userName);
            userInfo.appendChild(userEmail);
            
            // 2. Controls column (Role and Access)
            const userControls = document.createElement('div');
            userControls.className = 'user-controls';
            
            // Role control
            const roleControl = document.createElement('div');
            roleControl.className = 'control-group';
            
            const roleLabel = document.createElement('label');
            roleLabel.className = 'control-label';
            roleLabel.textContent = 'Role:';
            roleLabel.htmlFor = `role-select-${user.username}`;
            
            const roleSelect = document.createElement('select');
            roleSelect.className = 'role-select';
            roleSelect.id = `role-select-${user.username}`;
            roleSelect.dataset.username = user.username;
            
            // Add options
            const roles = ['user', 'admin', 'guest'];
            roles.forEach(role => {
                const option = document.createElement('option');
                option.value = role;
                option.textContent = role.charAt(0).toUpperCase() + role.slice(1);
                option.selected = user.role === role;
                roleSelect.appendChild(option);
            });
            
            // Add event listener for role change
            roleSelect.addEventListener('change', async function() {
                const username = this.dataset.username;
                const newRole = this.value;
                const isAllowed = document.getElementById(`access-toggle-${username}`).checked;
                
                try {
                    await updateUserAccess(username, isAllowed, newRole);
                } catch (error) {
                    console.error('Error updating role:', error);
                    this.value = user.role; // Reset to original value on error
                    showToast('Error updating role: ' + error.message, 'error');
                }
            });
            
            roleControl.appendChild(roleLabel);
            roleControl.appendChild(roleSelect);
            
            // Access toggle
            const accessControl = document.createElement('div');
            accessControl.className = 'control-group';
            
            const accessLabel = document.createElement('label');
            accessLabel.className = 'control-label';
            accessLabel.textContent = 'Access:';
            accessLabel.htmlFor = `access-toggle-${user.username}`;
            
            const toggleContainer = document.createElement('label');
            toggleContainer.className = 'toggle-switch';
            
            const accessToggle = document.createElement('input');
            accessToggle.type = 'checkbox';
            accessToggle.id = `access-toggle-${user.username}`;
            accessToggle.checked = user.allowed;
            accessToggle.dataset.username = user.username;
            accessToggle.dataset.role = user.role;
            
            // Disable toggle for admin users
            if (user.role === 'admin') {
                accessToggle.disabled = true;
                toggleContainer.title = 'Admin accounts must always have access';
            }
            
            const toggleSlider = document.createElement('span');
            toggleSlider.className = 'toggle-slider';
            
            // Add event listener for access toggle
            accessToggle.addEventListener('change', async function() {
                const username = this.dataset.username;
                const role = this.dataset.role;
                const isAllowed = this.checked;
                
                // Prevent disabling admin accounts
                if (!isAllowed && role === 'admin') {
                    alert('Cannot disable admin accounts. Admins must always have access.');
                    this.checked = true; // Reset to checked
                    return;
                }
                
                try {
                    await updateUserAccess(username, isAllowed, role);
                } catch (error) {
                    console.error('Error updating access:', error);
                    this.checked = user.allowed; // Reset to original value on error
                    showToast('Error updating access: ' + error.message, 'error');
                }
            });
            
            toggleContainer.appendChild(accessToggle);
            toggleContainer.appendChild(toggleSlider);
            
            accessControl.appendChild(accessLabel);
            accessControl.appendChild(toggleContainer);
            
            userControls.appendChild(roleControl);
            userControls.appendChild(accessControl);
            
            // 3. Type and status column
            const typeAndStatus = document.createElement('div');
            typeAndStatus.className = 'type-status';
            
            // User type badge
            const typeBadge = document.createElement('span');
            typeBadge.className = `user-type-badge ${user.userType === 'azure' ? 'azure' : 'local'}`;
            typeBadge.textContent = user.userType === 'azure' ? 'Azure' : 'Local';
            
            // Access status badge
            const accessBadge = document.createElement('span');
            accessBadge.className = `access-badge ${user.allowed ? 'allowed' : 'denied'}`;
            accessBadge.textContent = user.allowed ? 'Allowed' : 'Not Allowed';
            accessBadge.style.marginLeft = '8px';
            
            typeAndStatus.appendChild(typeBadge);
            typeAndStatus.appendChild(accessBadge);
            
            // 4. Last activity column
            const lastActivity = document.createElement('div');
            lastActivity.className = 'last-activity';
            lastActivity.textContent = user.lastLogin || 'Never';
            
            // Add everything to the user item
            userItem.appendChild(userInfo);
            userItem.appendChild(userControls);
            userItem.appendChild(typeAndStatus);
            userItem.appendChild(lastActivity);
            
            // Add the user item to the items container
            userItemsContainer.appendChild(userItem);
        });
        
        // Add the items container to the user list container
        userListContainer.appendChild(userItemsContainer);
        
        // Clear the container and add the new components
        tableContainer.innerHTML = '';
        tableContainer.appendChild(header);
        tableContainer.appendChild(userListContainer);
    } catch (error) {
        console.error('Error creating users list:', error);
        tableContainer.innerHTML = `<p>Error creating users list: ${error.message}</p>`;
    }
}

// Function to update user access with role
async function updateUserAccess(username, isAllowed, role) {
    if (!username) {
        throw new Error('Username is required to update access');
    }
    
    // Prevent disabling admin accounts
    if (!isAllowed && role === 'admin') {
        throw new Error('Cannot disable admin accounts. Admins must always have access.');
    }
    
    const statusElement = document.getElementById('debug-status');
    if (statusElement) {
        statusElement.textContent = `Updating ${username}: role=${role}, access=${isAllowed ? 'allowed' : 'not allowed'}...`;
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
            is_allowed: isAllowed,
            role: role
        })
    });
    
    if (!response.ok) {
        throw new Error(`HTTP error ${response.status}: ${await response.text()}`);
    }
    
    const data = await response.json();
    
    // Show success message
    if (statusElement) {
        statusElement.textContent = `Successfully updated ${username}: role=${role}, access=${isAllowed ? 'allowed' : 'not allowed'}`;
        statusElement.style.color = '#28a745';
    }
    
    // Show toast notification
    showToast(`User ${username} updated successfully`, 'success');
    
    // Reload users after a short delay
    setTimeout(async () => {
        await loadUsers();
    }, 1000);
    
    return data;
}

// Function to show toast notification
function showToast(message, type = 'info') {
    // Create toast container if it doesn't exist
    let toastContainer = document.getElementById('toast-container');
    if (!toastContainer) {
        toastContainer = document.createElement('div');
        toastContainer.id = 'toast-container';
        toastContainer.style.position = 'fixed';
        toastContainer.style.bottom = '20px';
        toastContainer.style.right = '20px';
        toastContainer.style.zIndex = '1000';
        document.body.appendChild(toastContainer);
    }
    
    // Create toast element
    const toast = document.createElement('div');
    toast.style.minWidth = '250px';
    toast.style.margin = '10px';
    toast.style.padding = '12px 16px';
    toast.style.borderRadius = '4px';
    toast.style.boxShadow = '0 4px 12px rgba(0,0,0,0.15)';
    toast.style.fontSize = '14px';
    toast.style.fontWeight = '500';
    toast.style.opacity = '0';
    toast.style.transition = 'opacity 0.3s, transform 0.3s';
    toast.style.transform = 'translateY(20px)';
    
    // Set toast color based on type
    if (type === 'success') {
        toast.style.backgroundColor = '#28a745';
        toast.style.color = 'white';
    } else if (type === 'error') {
        toast.style.backgroundColor = '#dc3545';
        toast.style.color = 'white';
    } else {
        toast.style.backgroundColor = '#17a2b8';
        toast.style.color = 'white';
    }
    
    // Set toast content
    toast.textContent = message;
    
    // Add toast to container
    toastContainer.appendChild(toast);
    
    // Show toast with animation
    setTimeout(() => {
        toast.style.opacity = '1';
        toast.style.transform = 'translateY(0)';
    }, 10);
    
    // Hide toast after 3 seconds
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(20px)';
        
        // Remove toast from DOM after animation completes
        setTimeout(() => {
            toastContainer.removeChild(toast);
        }, 300);
    }, 3000);
}

// Toggle a user's access - keep this for backward compatibility
async function toggleUserAccess(username, allow, role) {
    try {
        await updateUserAccess(username, allow, role);
    } catch (error) {
        console.error('Error toggling user access:', error);
        
        const statusElement = document.getElementById('debug-status');
        if (statusElement) {
            statusElement.textContent = `Error: ${error.message}`;
            statusElement.style.color = '#dc3545';
        }
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

// Add a function to run the backfill process
async function runBackfill() {
    const backfillStatus = document.getElementById('backfill-status');
    
    if (backfillStatus) {
        backfillStatus.textContent = 'Running backfill operation...';
        backfillStatus.style.color = '#6c757d';
    }
    
    const authToken = getAuthToken();
    
    try {
        const response = await fetch('/api/v2/users/backfill', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'authtoken': authToken
            }
        });
        
        if (response.ok) {
            const result = await response.json();
            console.log('Backfill result:', result);
            
            if (backfillStatus) {
                if (result.success) {
                    const successCount = result.details?.success_count || 0;
                    const errorCount = result.details?.error_count || 0;
                    const totalProcessed = successCount + errorCount;
                    
                    backfillStatus.textContent = `Backfill completed successfully. Processed ${totalProcessed} users (${successCount} succeeded, ${errorCount} failed).`;
                    backfillStatus.style.color = '#28a745';
                } else {
                    backfillStatus.textContent = result.message || 'Backfill completed with unknown result.';
                    backfillStatus.style.color = '#ffc107';
                }
            }
            
            // Reload users to show any newly backfilled users
            setTimeout(loadUsers, 1000);
        } else {
            const errorText = await response.text();
            console.error('Error running backfill:', errorText);
            
            if (backfillStatus) {
                backfillStatus.textContent = `Error: ${response.status} - ${errorText}`;
                backfillStatus.style.color = '#dc3545';
            }
        }
    } catch (error) {
        console.error('Error running backfill:', error);
        
        if (backfillStatus) {
            backfillStatus.textContent = `Error: ${error.message}`;
            backfillStatus.style.color = '#dc3545';
        }
    }
}

// Add a debug toggle function
function toggleDebugInfo() {
    const debugPanel = document.getElementById('debug-panel');
    const debugStatus = document.getElementById('debug-status');
    
    if (!debugPanel) {
        console.error('Debug panel not found');
        return;
    }
    
    const isVisible = debugPanel.style.display !== 'none';
    
    if (isVisible) {
        // Hide the panel
        debugPanel.style.display = 'none';
        if (debugStatus) {
            debugStatus.textContent = 'Debug information hidden';
            debugStatus.style.color = '#6c757d';
        }
    } else {
        // Show the panel and fetch data
        debugPanel.style.display = 'block';
        if (debugStatus) {
            debugStatus.textContent = 'Debug information visible';
            debugStatus.style.color = '#28a745';
        }
        
        // Fetch debug data
        fetchDebugData();
    }
}

// Fetch debug data for display
async function fetchDebugData() {
    const debugInfoElement = document.getElementById('debug-info');
    const debugContent = document.getElementById('debug-content');
    
    if (!debugInfoElement) {
        console.error('Debug info element not found');
        return;
    }
    
    debugInfoElement.textContent = 'Loading debug information...';
    
    // Add current debug information
    let debugOutput = JSON.stringify(debugInfo, null, 2);
    
    // Add local storage token information
    let tokenInfo = {
        auth_token: !!localStorage.getItem('timetagger_auth_token'),
        user_info: localStorage.getItem('timetagger_user_info'),
        webtoken_azure: !!localStorage.getItem('timetagger_webtoken_azure')
    };
    
    debugInfo.localStorageInfo = tokenInfo;
    
    // Update the debug info display
    debugInfoElement.textContent = JSON.stringify(debugInfo, null, 2);
    
    if (debugContent) {
        // Add more debug content
        let currentUserInfo = '';
        try {
            const userInfoJson = localStorage.getItem('timetagger_user_info');
            if (userInfoJson) {
                const userInfo = JSON.parse(userInfoJson);
                currentUserInfo = `
                    <div style="margin-top: 15px;">
                        <h4>Current User Info</h4>
                        <pre style="font-family: monospace; white-space: pre-wrap; background-color: #f8f9fa; padding: 15px; border-radius: 4px;">${JSON.stringify(userInfo, null, 2)}</pre>
                    </div>
                `;
            }
        } catch (e) {
            currentUserInfo = `<p>Error parsing user info: ${e.message}</p>`;
        }
        
        debugContent.innerHTML = `
            <div>
                <h4>LocalStorage Data</h4>
                <pre style="font-family: monospace; white-space: pre-wrap; background-color: #f8f9fa; padding: 15px; border-radius: 4px;">${JSON.stringify(tokenInfo, null, 2)}</pre>
            </div>
            ${currentUserInfo}
        `;
    }
}

// Add a new button for debugging Azure users specifically
async function debugAzureUsers() {
    const debugStatus = document.getElementById('debug-status');
    
    if (debugStatus) {
        debugStatus.textContent = 'Fetching Azure user debug information...';
        debugStatus.style.color = '#6c757d';
    }
    
    const authToken = getAuthToken();
    
    try {
        const response = await fetch('/api/v2/users/debug-azure', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'authtoken': authToken
            }
        });
        
        if (response.ok) {
            const data = await response.json();
            console.log('Azure users debug data:', data);
            
            // Show the debug panel if not already visible
            const debugPanel = document.getElementById('debug-panel');
            if (debugPanel) {
                debugPanel.style.display = 'block';
            }
            
            // Update the debug info display
            const debugInfoElement = document.getElementById('debug-info');
            if (debugInfoElement) {
                debugInfoElement.textContent = JSON.stringify(data.debug_info, null, 2);
            }
            
            if (debugStatus) {
                const azureCount = data.debug_info?.azure_users?.length || 0;
                const localCount = data.debug_info?.local_users?.length || 0;
                
                debugStatus.textContent = `Debug completed: Found ${azureCount} Azure users and ${localCount} local users in database.`;
                debugStatus.style.color = '#28a745';
            }
        } else {
            const errorText = await response.text();
            console.error('Error fetching Azure user debug data:', errorText);
            
            if (debugStatus) {
                debugStatus.textContent = `Error: ${response.status} - ${errorText}`;
                debugStatus.style.color = '#dc3545';
            }
        }
    } catch (error) {
        console.error('Error debugging Azure users:', error);
        
        if (debugStatus) {
            debugStatus.textContent = `Error: ${error.message}`;
            debugStatus.style.color = '#dc3545';
        }
    }
}

// Search users based on the search input
function searchUsers() {
    const searchInput = document.getElementById('search-input');
    const searchTerm = searchInput.value.trim().toLowerCase();
    
    if (!searchTerm) {
        // If search term is empty, show all users
        loadUsers();
        return;
    }
    
    try {
        // Get the user items
        const userList = document.querySelector('.user-list');
        if (!userList) {
            console.error('No user list found');
            return;
        }
        
        const userItems = Array.from(userList.querySelectorAll('.user-item'));
        
        // Skip the header
        const listHeader = userList.querySelector('.list-header');
        if (listHeader) {
            userItems.shift();
        }
        
        // Counter for matching users
        let matchingUsers = 0;
        
        // Filter items based on search term
        userItems.forEach(item => {
            // Get user info from the item
            const name = item.querySelector('.user-name').textContent.toLowerCase();
            const email = item.querySelector('.user-email').textContent.toLowerCase();
            const role = item.querySelector('select.role-select').value.toLowerCase();
            const userType = item.querySelector('.user-type-badge').textContent.toLowerCase();
            
            // If the search term is found in any of the fields, show the item
            if (name.includes(searchTerm) || 
                email.includes(searchTerm) || 
                role.includes(searchTerm) || 
                userType.includes(searchTerm)) {
                item.style.display = '';
                matchingUsers++;
            } else {
                item.style.display = 'none';
            }
        });
        
        // Update header with filtered count
        const usersSection = document.getElementById('users-section');
        const header = usersSection.querySelector('h3');
        if (header) {
            header.textContent = `Users (${matchingUsers} matching "${searchTerm}")`;
        }
        
        // Show status message
        const statusElement = document.getElementById('debug-status');
        if (statusElement) {
            statusElement.textContent = `Found ${matchingUsers} users matching "${searchTerm}"`;
            statusElement.style.color = matchingUsers > 0 ? '#28a745' : '#dc3545';
        }
        
    } catch (error) {
        console.error('Error searching users:', error);
        const statusElement = document.getElementById('debug-status');
        if (statusElement) {
            statusElement.textContent = `Error searching: ${error.message}`;
            statusElement.style.color = '#dc3545';
        }
    }
}

// Clear search and reload all users
function clearSearch() {
    const searchInput = document.getElementById('search-input');
    searchInput.value = '';
    
    // Reset header text
    const usersSection = document.getElementById('users-section');
    const header = usersSection.querySelector('h3');
    if (header) {
        const tableContainer = document.getElementById('users-table-container');
        const userList = tableContainer.querySelector('.user-list');
        if (userList) {
            const userItems = userList.querySelectorAll('.user-item');
            if (userItems.length > 0) {
                // Adjust for header item
                header.textContent = `All Users (${userItems.length - 1} total)`;
            }
        }
    }
    
    // Show all users
    loadUsers();
}
</script>