import httpx
import json

response = httpx.get("http://localhost:8000/timetagger/api/v2/public_auth_config")
print("HTTP Status:", response.status_code)

if response.status_code == 200:
    try:
        data = response.json()
        print("\nPublic Auth Config:")
        print(json.dumps(data, indent=2))
        
        # Verify no sensitive information is exposed
        if "azure_client_secret" not in data:
            print("\n✓ No client secret exposed")
        else:
            print("\n❌ Client secret is exposed!")
            
        if not data.get("azure_client_id") and not data.get("azure_tenant_id"):
            print("✓ No credentials exposed")
        else:
            print("❌ Some credentials may be exposed")
    except Exception as e:
        print(f"Error parsing response: {e}")
else:
    print("Failed to get public auth config") 