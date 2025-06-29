import requests
import json

BASE_URL = "http://127.0.0.1:8000/api"

# --- Step 1: Super Admin Login (Get OTP) ---
print("--- Step 1: Super Admin Login (Get OTP) ---")
super_admin_credentials = {
    "username": "Samip_5",
    "password": "Samip_5"
}
try:
    response = requests.post(f"{BASE_URL}/auth/super-admin/login/", json=super_admin_credentials)
    response.raise_for_status()  # Raise an exception for bad status codes
    print("OTP Request successful.")
    print(f"Response: {response.json()}")
except requests.exceptions.RequestException as e:
    print(f"An error occurred: {e}")
    if e.response:
        print(f"Response Body: {e.response.text}")

# --- Step 2: Super Admin Login (Verify OTP) ---
print("\n--- Step 2: Super Admin Login (Verify OTP) ---")
otp = input("Please enter the OTP from the console: ")
otp_payload = {
    "username": "Samip_5",
    "otp": otp
}
try:
    response = requests.post(f"{BASE_URL}/auth/super-admin/verify/", json=otp_payload)
    response.raise_for_status()
    super_admin_token = response.json().get("token")
    print("OTP Verification successful.")
    print(f"Super Admin Token: {super_admin_token}")
except requests.exceptions.RequestException as e:
    print(f"An error occurred: {e}")
    if e.response:
        print(f"Response Body: {e.response.text}")
    super_admin_token = None

# --- Step 3: Create Organization ---
if super_admin_token:
    print("\n--- Step 3: Create Organization ---")
    org_payload = {
        "org_name": "TestCorp",
        "admin_email": "test_admin@testcorp.com",
        "admin_password": "test_password",
        "admin_password_confirm": "test_password"
    }
    headers = {"Authorization": f"Token {super_admin_token}"}
    try:
        response = requests.post(f"{BASE_URL}/org/register-organization/", json=org_payload, headers=headers)
        response.raise_for_status()
        print("Organization Creation successful.")
        print(f"Response: {response.json()}")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        if e.response:
            print(f"Response Body: {e.response.text}")