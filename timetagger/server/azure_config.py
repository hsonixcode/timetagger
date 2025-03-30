"""
Azure AD configuration for TimeTagger.
"""

import os

def get_azure_config():
    """Get Azure AD configuration from environment variables."""
    return {
        'azure_client_id': os.environ.get('TIMETAGGER_AZURE_CLIENT_ID', ''),
        'azure_tenant_id': os.environ.get('TIMETAGGER_AZURE_TENANT_ID', '')
    }