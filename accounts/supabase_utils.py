import requests

SUPABASE_URL = "https://quyikbogueqkbowxjxzg.supabase.co"
SUPABASE_API_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" \
".eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InF1eWlrYm9ndWVxa2Jvd3hqeHpnIiwicm9s" \
"ZSI6ImFub24iLCJpYXQiOjE3NDc4MTE4NzgsImV4cCI6MjA2MzM4Nzg3OH0.MwE3B5GrMXad" \
"WongyNVX9mia3Jta5e9uqO-v_pkPoU8"

def insert_public_key(email, role, public_key):
    url = f"{SUPABASE_URL}/rest/v1/users"

    headers = {
        "apikey": SUPABASE_API_KEY,
        "Authorization": f"Bearer {SUPABASE_API_KEY}",
        "Content-Type": "application/json",
        "Prefer": "return=minimal"
    }

    data = {
        "email": email,
        "role": role,
        "public_key": public_key
    }

    response = requests.post(url, json=data, headers=headers)
    return response.status_code, response.text
