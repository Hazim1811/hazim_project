import requests

SUPABASE_URL = "https://quyikbogueqkbowxjxzg.supabase.co"
SUPABASE_API_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" \
".eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InF1eWlrYm9ndWVxa2Jvd3hqeHpnIiwicm9s" \
"ZSI6ImFub24iLCJpYXQiOjE3NDc4MTE4NzgsImV4cCI6MjA2MzM4Nzg3OH0.MwE3B5GrMXad" \
"WongyNVX9mia3Jta5e9uqO-v_pkPoU8"

def insert_public_key(email, role, public_key):
    url = f"{SUPABASE_URL}/rest/v1/user_keys"

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
    print(f"[SUPABASE POST] Pushed public key for {email} | Status: {response.status_code}")
    print(f"[SUPABASE BODY] {data}")
    print(f"[SUPABASE RESPONSE] {response.text}")

    return response.status_code, response.text


def sync_patient(data):
    base = f"{SUPABASE_URL}/rest/v1/accounts_patient"
    headers = {
        "apikey": SUPABASE_API_KEY,
        "Authorization": f"Bearer {SUPABASE_API_KEY}",
        "Content-Type": "application/json",
    }

    # First try to update
    resp = requests.patch(
        f"{base}?patient_id=eq.{data['patient_id']}",
        json=data,
        headers=headers
    )
    if resp.status_code in (200, 204):
        return True, resp.status_code, resp.text

    # If no row was found/updated, fall back to insert
    resp = requests.post(
        base,
        json=[data],
        headers={**headers, "Prefer": "return=minimal"}
    )
    success = resp.status_code in (200, 201, 204)
    return success, resp.status_code, resp.text



def delete_patient_record(patient_id):
    url = f"{SUPABASE_URL}/rest/v1/accounts_patient?patient_id=eq.{patient_id}"

    headers = {
        "apikey": SUPABASE_API_KEY,
        "Authorization": f"Bearer {SUPABASE_API_KEY}"
    }

    response = requests.delete(url, headers=headers)
    success = response.status_code in [200, 204]
    return success,response.status_code, response.text
