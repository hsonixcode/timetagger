% Admin Dashboard
% Manage TimeTagger users and configuration.

<div id="admin-panel" style="padding: 2em; border: 1px solid #ccc; border-radius: 5px; max-width: 800px; margin: 2em auto;">
    <h2>Admin Dashboard</h2>
    <p id="status" style="color: green; font-weight: bold;"></p>

    <div id="users-section" style="margin-bottom: 2em;">
        <h3>Users</h3>
        <div id="users-list" style="margin-top: 1em;">
            Loading users...
        </div>
    </div>

    <div id="admin-links" style="margin-top: 2em; padding-top: 1em; border-top: 1px solid #eee;">
        <h3>Administration</h3>
        <ul>
            <li><a href="/timetagger/configure_external_auth">Configure Azure AD Authentication</a></li>
        </ul>
    </div>
</div>

<script>
// Get auth token from localStorage
function getAuthToken() {
    return localStorage.getItem('timetagger_auth_token');
}

async function loadUsers() {
    const statusElement = document.getElementById('status');
    const usersListElement = document.getElementById('users-list');

    try {
        const authToken = getAuthToken();
        if (!authToken) {
            throw new Error('No authentication token found. Please log in again.');
        }

        // Decode the JWT token to check admin status
        const tokenParts = authToken.split('.');
        const payload = JSON.parse(atob(tokenParts[1]));
        if (!payload.is_admin) {
            throw new Error('Only admin users can access this page.');
        }

        // Get list of users from the server
        const response = await fetch('/api/v2/users', {
            headers: {
                'authtoken': authToken
            }
        });

        if (!response.ok) {
            throw new Error(`HTTP error ${response.status}: ${await response.text()}`);
        }
        
        const users = await response.json();
        
        // Create a table to display users
        let html = `
            <table style="width: 100%; border-collapse: collapse;">
                <thead>
                    <tr>
                        <th style="text-align: left; padding: 8px; border-bottom: 2px solid #ddd;">Username</th>
                        <th style="text-align: left; padding: 8px; border-bottom: 2px solid #ddd;">Role</th>
                        <th style="text-align: left; padding: 8px; border-bottom: 2px solid #ddd;">Last Active</th>
                    </tr>
                </thead>
                <tbody>
        `;

        users.forEach(user => {
            const isAdmin = user.is_admin ? 'Admin' : 'User';
            const lastActive = user.last_active ? new Date(user.last_active * 1000).toLocaleString() : 'Never';
            html += `
                <tr>
                    <td style="padding: 8px; border-bottom: 1px solid #ddd;">${user.username}</td>
                    <td style="padding: 8px; border-bottom: 1px solid #ddd;">${isAdmin}</td>
                    <td style="padding: 8px; border-bottom: 1px solid #ddd;">${lastActive}</td>
                </tr>
            `;
        });

        html += '</tbody></table>';
        usersListElement.innerHTML = html;

    } catch (error) {
        console.error("Error loading users:", error);
        statusElement.textContent = `Error: ${error.message}`;
        statusElement.style.color = 'red';
        
        // If not admin, hide the content and show error
        if (error.message.includes('Only admin users')) {
            document.getElementById('users-section').style.display = 'none';
            document.getElementById('admin-links').style.display = 'none';
        }
    }
}

// Load users when the page loads
window.addEventListener('load', loadUsers);
</script> 