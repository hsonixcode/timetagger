import os
import json
import logging
from typing import Dict, Optional
from dataclasses import dataclass
from sqlalchemy import create_engine, Column, String, JSON, DateTime, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
from ratelimit import limits, sleep_and_retry
import httpx
from urllib.parse import urlencode
from werkzeug.exceptions import BadRequest, Forbidden, InternalServerError

from .. import config
from ._utils import logger as base_logger
from ._apiserver import AuthException

# Set up logging - try to use structlog if available, fall back to standard logging
try:
    import structlog
    logger = structlog.get_logger()
except ImportError:
    logger = base_logger

# Initialize SQLAlchemy with proper error handling
try:
    db_url = os.environ.get('TIMETAGGER_DB_URL')
    if not db_url:
        raise ValueError("TIMETAGGER_DB_URL environment variable is not set")
    
    logger.info("Attempting database connection with URL: " + 
                db_url.replace(os.environ.get('POSTGRES_PASSWORD', ''), '***'))
    
    Base = declarative_base()
    engine = create_engine(db_url)
    
    # Test the connection using SQLAlchemy 2.0 style
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
        conn.commit()
        logger.info("Database connection test successful")
    
    Session = sessionmaker(bind=engine)
    logger.info("Database connection and session factory established successfully")
    
except Exception as e:
    logger.error("Failed to initialize database: " + str(e))
    raise

class AppConfig(Base):
    """Model for storing application configuration."""
    __tablename__ = 'app_config'
    
    key = Column(String, primary_key=True)
    value = Column(JSON, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# Create database indexes using SQLAlchemy 2.0 style
def create_indexes():
    """Create indexes for frequently accessed fields."""
    with engine.connect() as conn:
        conn.execute(text("""
        CREATE INDEX IF NOT EXISTS idx_app_config_key ON app_config(key);
        CREATE INDEX IF NOT EXISTS idx_app_config_updated_at ON app_config(updated_at);
        """))
        conn.commit()

# Initialize database and indexes
Base.metadata.create_all(engine)
create_indexes()

# Rate limits for config endpoints
@sleep_and_retry
@limits(calls=10, period=60)  # 10 calls per minute
def rate_limited_config_access():
    pass

@dataclass
class PublicAuthConfig:
    """Data class for public authentication configuration."""
    azure_auth_enabled: bool
    azure_client_id: Optional[str]
    azure_tenant_id: Optional[str]
    azure_instance: Optional[str]
    azure_redirect_uri: Optional[str]

def get_public_auth_config() -> Dict:
    """Get public application configuration for authentication.
    This is a public endpoint for clients to determine authentication options.
    
    Sensitive secrets like client_secret are removed from the response.
    
    Returns:
        Dict: The public application configuration for authentication
    """
    rate_limited_config_access()  # Apply rate limiting
    
    try:
        # Check for a special request parameter to force disable Azure AD
        if os.path.exists('/app/timetagger-server/.data/force_disable_azure'):
            logger.warning("Found force_disable_azure file - forcing Azure AD disabled in config")
            return {
                'azure_auth_enabled': False,
                'azure_client_id': None,
                'azure_tenant_id': None,
                'azure_instance': 'https://login.microsoftonline.com',
                'azure_redirect_uri': None
            }
            
        session = Session()
        config = session.query(AppConfig).filter_by(key='auth_config').first()
        
        # Default configuration if none exists
        public_config = {
            'azure_auth_enabled': False,
            'azure_client_id': None,
            'azure_tenant_id': None,
            'azure_instance': 'https://login.microsoftonline.com',
            'azure_redirect_uri': None
        }
        
        # Override with stored configuration if it exists
        if config and config.value:
            # Make a clean copy to avoid mutation issues
            stored_config = dict(config.value)
            
            # Only show Azure AD as enabled if both flag is true AND credentials are provided
            if stored_config.get('azure_auth_enabled', False):
                has_client_id = bool(stored_config.get('azure_client_id', '').strip())
                has_tenant_id = bool(stored_config.get('azure_tenant_id', '').strip())
                
                # If credentials are missing, override the enabled flag
                if not (has_client_id and has_tenant_id):
                    stored_config['azure_auth_enabled'] = False
                    logger.warning("Azure AD configuration is incomplete - reporting as disabled")
            
            public_config.update(stored_config)
            
        # Always ensure sensitive data is removed
        public_config.pop('azure_client_secret', None)
        
        # Force Azure AD to be reported as disabled
        public_config['azure_auth_enabled'] = False
        logger.info(f"Public auth config requested, Azure FORCED TO disabled")
        
        return public_config
        
    except Exception as e:
        logger.error("public_auth_config.error",
                    error=str(e),
                    error_type=type(e).__name__)
        raise
    finally:
        session.close()

def get_full_app_config(auth_info: dict, bypass_admin_check: bool = False) -> Dict:
    """Get full application configuration including secrets.
    Only accessible by admin users or internal system calls with bypass flag.
    
    Args:
        auth_info: The authentication info dictionary
        bypass_admin_check: If True, skip the admin check (for internal system operations)
    
    Returns:
        Dict: The complete application configuration
    """
    rate_limited_config_access()  # Apply rate limiting
    
    # Skip admin check if bypass flag is set
    if not bypass_admin_check:
        # Use the synchronous admin check function
        from timetagger.multiuser.auth_utils import check_admin_status_sync
        
        is_admin, source = check_admin_status_sync(auth_info)
        
        # Verify admin access
        if not is_admin:
            logger.warning("app_config.unauthorized_access",
                          user=auth_info.get('username'),
                          source=source)
            raise AuthException("Only admin users can access full configuration")
        
        logger.info(f"Admin access granted to {auth_info.get('username')} (source: {source})")
    else:
        logger.info("Admin check bypassed for system operation")
    
    try:
        session = Session()
        config = session.query(AppConfig).filter_by(key='auth_config').first()
        
        logger.info("app_config.access",
                   user=auth_info.get('username'),
                   config_exists=bool(config))
        
        if not config:
            # Return default config if none exists
            return {
                'azure_auth_enabled': False,
                'azure_client_id': None,
                'azure_client_secret': None,
                'azure_tenant_id': None,
                'azure_instance': 'https://login.microsoftonline.com',
                'azure_redirect_uri': None
            }
        
        return config.value
        
    except Exception as e:
        logger.error("app_config.error",
                    user=auth_info.get('username'),
                    error=str(e),
                    error_type=type(e).__name__)
        raise
    finally:
        session.close()

def validate_redirect_uri(uri: str) -> bool:
    """Validate the redirect URI against allowed domains."""
    allowed_domains = [
        "localhost",
        "127.0.0.1",
        # Add your production domains here
    ]
    from urllib.parse import urlparse
    parsed = urlparse(uri)
    return any(domain in parsed.netloc for domain in allowed_domains)

def update_app_config(auth_info: dict, new_config: Dict) -> Dict:
    """Update application configuration.
    Only accessible by admin users."""
    rate_limited_config_access()  # Apply rate limiting
    
    # Check if the user is an admin directly from auth_info
    is_admin = auth_info.get('is_admin', False)
    
    # If not admin according to auth_info, check the JWT token if available
    if not is_admin and 'token' in auth_info:
        try:
            import json
            import base64
            # Get the payload part of the JWT token
            token_parts = auth_info['token'].split('.')
            if len(token_parts) >= 2:
                # Ensure correct padding for base64 decoding
                payload_b64 = token_parts[1]
                payload_b64 += '=' * (-len(payload_b64) % 4)
                # Decode the payload and extract the is_admin flag
                token_payload = json.loads(base64.urlsafe_b64decode(payload_b64))
                is_admin = token_payload.get('is_admin', False)
                logger.info(f"Admin check from JWT token: {is_admin}")
        except Exception as e:
            logger.error(f"Error extracting admin status from token: {str(e)}")
    
    # Also check for admin role in the database for Azure users
    if not is_admin and auth_info.get('username'):
        from timetagger.multiuser.login_tracker import LoginTracker
        try:
            tracker = LoginTracker()
            user = tracker.get_login_by_email(auth_info.get('username'))
            if user and user.get('role') == 'admin':
                is_admin = True
                logger.info(f"Admin check from database: user {auth_info.get('username')} has admin role")
        except Exception as e:
            logger.error(f"Error checking admin role from database: {str(e)}")
    
    # Verify admin access
    if not is_admin:
        logger.warning("app_config.unauthorized_update",
                      user=auth_info.get('username'))
        raise AuthException("Only admin users can update configuration")
    
    try:
        session = Session()
        
        # Handle both nested and flat config structures
        config_value = new_config
        if 'value' in new_config and isinstance(new_config['value'], dict):
            # If nested in a 'value' field, use that
            config_value = new_config['value']
            logger.info("Found nested config in 'value' field")
        
        # Validate config structure
        required_fields = {'azure_auth_enabled', 'azure_client_id', 'azure_tenant_id', 'azure_instance', 'azure_redirect_uri'}
        missing_fields = [field for field in required_fields if field not in config_value]
        if missing_fields:
            logger.error("app_config.validation_error",
                        user=auth_info.get('username'),
                        missing_fields=missing_fields)
            raise ValueError(f"Missing required fields: {', '.join(missing_fields)}")
        
        # Validate redirect URI
        if not validate_redirect_uri(config_value.get('azure_redirect_uri', '')):
            logger.error("app_config.invalid_redirect_uri",
                        user=auth_info.get('username'),
                        uri=config_value.get('azure_redirect_uri'))
            raise ValueError("Invalid redirect URI")
        
        # Get or create config
        config = session.query(AppConfig).filter_by(key='auth_config').first()
        if not config:
            config = AppConfig(key='auth_config', value={})
            session.add(config)
        
        # Update config
        config.value = config_value
        session.commit()
        
        logger.info("app_config.updated",
                   user=auth_info.get('username'),
                   azure_enabled=config_value.get('azure_auth_enabled'))
        
        return config.value
        
    except Exception as e:
        session.rollback()
        logger.error("app_config.update_error",
                    user=auth_info.get('username'),
                    error=str(e),
                    error_type=type(e).__name__)
        raise
    finally:
        session.close()

async def test_azure_config(config: Dict) -> Dict:
    """Test Azure AD configuration by attempting to get an access token.
    This is a public endpoint to test Azure AD configuration."""
    rate_limited_config_access()  # Apply rate limiting
    
    try:
        # Validate required fields
        required_fields = {'azure_client_id', 'azure_tenant_id', 'azure_client_secret', 'azure_instance'}
        missing_fields = [field for field in required_fields if not config.get(field)]
        if missing_fields:
            return {
                'success': False,
                'error': f"Missing required fields: {', '.join(missing_fields)}"
            }
        
        # Construct token endpoint URL
        token_endpoint = f"{config['azure_instance']}/{config['azure_tenant_id']}/oauth2/v2.0/token"
        
        # Prepare token request data
        token_data = {
            'client_id': config['azure_client_id'],
            'client_secret': config['azure_client_secret'],
            'scope': 'https://graph.microsoft.com/.default',
            'grant_type': 'client_credentials'
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                token_endpoint,
                data=token_data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            
            if response.status_code == 200:
                return {
                    'success': True,
                    'message': 'Successfully connected to Azure AD'
                }
            else:
                error_data = response.json()
                error_description = error_data.get('error_description', 'Unknown error')
                return {
                    'success': False,
                    'error': f"Azure AD error: {error_description}"
                }
                
    except httpx.RequestError as e:
        logger.error("azure_config.test_error",
                    error=str(e))
        return {
            'success': False,
            'error': f"Connection error: {str(e)}"
        }
    except Exception as e:
        logger.error("azure_config.test_error",
                    error=str(e))
        return {
            'success': False,
            'error': f"Unexpected error: {str(e)}"
        }

def get_users(request):
    """Get list of users. Only accessible by admin users."""
    auth_info = request.get('auth_info', {})
    if not auth_info.get('is_admin', False):
        raise Forbidden("Only admin users can access this endpoint")
    
    # Return list of users from credentials
    return list(CREDENTIALS.keys()) if CREDENTIALS else [] 