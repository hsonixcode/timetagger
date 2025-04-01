import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text
import json

# Setup database connection
engine = sa.create_engine('postgresql://timetagger:timetagger@postgres:5432/timetagger')
Session = sessionmaker(bind=engine)
session = Session()

print("Cleaning database of sensitive data...")

# 1. Clean login_users table - keep only admin user
try:
    session.execute(text("DELETE FROM login_users WHERE username != 'admin'"))
    print("✓ Removed all non-admin users")
except Exception as e:
    print(f"Error cleaning login_users: {e}")

# 2. Update app config to remove Azure credentials
try:
    # Get current config
    result = session.execute(text("SELECT key, value FROM app_config WHERE key = 'auth_config'"))
    row = result.fetchone()
    
    if row:
        # Parse the JSON value
        config_value = row[1]  # Access by index instead of column name
        
        # Update Azure settings to be empty/safe
        config_value['azure_auth_enabled'] = False
        config_value['azure_client_id'] = ''
        config_value['azure_client_secret'] = ''
        config_value['azure_tenant_id'] = ''
        config_value['azure_instance'] = 'https://login.microsoftonline.com'
        config_value['azure_redirect_uri'] = 'http://localhost:8000/timetagger/auth/callback'
        
        # Update the record with the modified JSON
        session.execute(
            text("UPDATE app_config SET value = :value WHERE key = 'auth_config'"),
            {"value": json.dumps(config_value)}
        )
        print("✓ Removed sensitive Azure credentials")
    else:
        print("No auth_config found to clean")
except Exception as e:
    print(f"Error cleaning app_config: {e}")

# 3. Clean user_info table
try:
    session.execute(text("DELETE FROM user_info WHERE username != 'admin'"))
    print("✓ Removed non-admin user info")
except Exception as e:
    print(f"Error cleaning user_info: {e}")

# 4. Remove any sensitive tags from records
try:
    session.execute(text("UPDATE records SET ds = REPLACE(ds, 'API_KEY', 'REDACTED') WHERE ds LIKE '%API_KEY%'"))
    session.execute(text("UPDATE records SET ds = REPLACE(ds, 'PASSWORD', 'REDACTED') WHERE ds LIKE '%PASSWORD%'"))
    session.execute(text("UPDATE records SET ds = REPLACE(ds, 'SECRET', 'REDACTED') WHERE ds LIKE '%SECRET%'"))
    print("✓ Redacted sensitive information from records")
except Exception as e:
    print(f"Error redacting sensitive data: {e}")

# Commit all changes
try:
    session.commit()
    print("✓ All changes committed")
except Exception as e:
    session.rollback()
    print(f"Error committing changes: {e}")
finally:
    session.close()

print("Database cleanup complete!") 