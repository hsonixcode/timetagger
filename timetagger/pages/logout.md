% Time Tracker - Logout
% Logging out of the Time Tracker application.

<div style="text-align: center; margin: 2em;">
    <h2>Logging out...</h2>
    <p>Please wait while we securely log you out.</p>
</div>

<script>
// Function to clear all authentication tokens
function clearAuthTokens() {
    // Clear Azure AD tokens
    localStorage.removeItem('azure_access_token');
    localStorage.removeItem('azure_id_token');
    localStorage.removeItem('azure_refresh_token');
    localStorage.removeItem('azure_token_expires_at');
    localStorage.removeItem('azure_auth_state');
    localStorage.removeItem('azure_original_page');
    
    // Clear TimeTagger tokens if they exist
    if (window.tools && typeof window.tools.set_auth === 'function') {
        window.tools.set_auth(null);
    }
    
    console.log('All authentication tokens cleared');
}

// Perform logout
function performLogout() {
    clearAuthTokens();
    
    // Add a small delay for visual feedback
    setTimeout(() => {
        // Redirect to login page with a message
        window.location.href = '/timetagger/login?message=logged_out';
    }, 1000);
}

// Execute logout when page loads
window.addEventListener('load', performLogout);
</script>

<style>
/* Add some styling for the logout message */
h2 {
    color: #333;
    margin-bottom: 1em;
}
p {
    color: #666;
}
</style>
