import sqlalchemy as sa
from sqlalchemy import text

# Setup database connection
engine = sa.create_engine('postgresql://timetagger:timetagger@postgres:5432/timetagger')
conn = engine.connect()

print("=== VERIFICATION OF DATABASE CLEANUP ===")

# Check login_users table
result = conn.execute(text("SELECT username FROM login_users"))
users = [row[0] for row in result]

print(f"\nUsers remaining in login_users table: {users}")
if len(users) == 1 and 'admin' in users:
    print("✓ Only admin user remains in login_users table")
else:
    print("❌ Other users still exist in login_users table")

# Check app_config - Azure settings
result = conn.execute(text("SELECT value FROM app_config WHERE key = 'auth_config'"))
row = result.fetchone()

if row:
    config = row[0]
    print("\nAzure AD configuration:")
    print(f"  Enabled: {config.get('azure_auth_enabled', 'N/A')}")
    print(f"  Client ID: {'[EMPTY]' if not config.get('azure_client_id') else '[PRESENT]'}")
    print(f"  Client Secret: {'[EMPTY]' if not config.get('azure_client_secret') else '[PRESENT]'}")
    print(f"  Tenant ID: {'[EMPTY]' if not config.get('azure_tenant_id') else '[PRESENT]'}")
    
    # Verify all credentials are empty
    if (not config.get('azure_auth_enabled') and
        not config.get('azure_client_id') and
        not config.get('azure_client_secret') and
        not config.get('azure_tenant_id')):
        print("✓ Azure credentials have been removed")
    else:
        print("❌ Some Azure credentials still exist")
else:
    print("\n❌ No auth_config found")

# Check user_info table
result = conn.execute(text("SELECT username FROM user_info"))
user_info_users = [row[0] for row in result]

print(f"\nUsers in user_info table: {user_info_users}")
if len(user_info_users) <= 1 and (not user_info_users or 'admin' in user_info_users):
    print("✓ No non-admin users in user_info table")
else:
    print("❌ Non-admin users still exist in user_info table")

# Close connection
conn.close()
print("\n=== VERIFICATION COMPLETE ===") 