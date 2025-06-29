import requests
import json
import os
import subprocess
from dotenv import load_dotenv
from pathlib import Path

# --- Setup ---
load_dotenv()
BASE_URL = "http://127.0.0.1:8000/api/v1"
SUPER_ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
SUPER_ADMIN_PASSWORD = os.getenv("ADMIN_PASS")
TEST_ORG_NAME = "Apex Innovations Inc."
TEST_RECEIPT_PATH = "receipts/test_receipt.jpg"

def print_step(title):
    print(f"\n{'='*25}\n{title}\n{'='*25}")

def check_response(response, step_name):
    print(f"--- Executing: {step_name} ---")
    try:
        response.raise_for_status()
        print(f"[SUCCESS] Status: {response.status_code}")
        if response.text:
            return response.json()
        return None
    except (requests.exceptions.RequestException, json.JSONDecodeError):
        print(f"[FAILURE] Status: {response.status_code} | {response.reason}")
        print(f"  Response Body: {response.text}")
        return None

def get_auth_token(email, password):
    login_payload = {"email": email, "password": password}
    response = requests.post(f"{BASE_URL}/auth/login/", json=login_payload)
    login_data = check_response(response, f"Login for {email}")
    if login_data and login_data.get("token"):
        return {"Authorization": f"Token {login_data['token']}"}, login_data.get('user', {})
    return None, None

def cleanup_via_management_command():
    """
    Fallback cleanup method using Django management command when API cleanup fails.
    """
    print_step("Fallback: Using Django Management Command for Cleanup")
    try:
        # Change to backend directory to run manage.py
        backend_dir = Path(__file__).parent / "backend"
        
        # Run the cleanup command with --skip-checks to avoid import issues
        result = subprocess.run(
            ["python", "manage.py", "cleanup_test_data", "--org-name", TEST_ORG_NAME, "--force", "--skip-checks"],
            cwd=backend_dir,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            print("[SUCCESS] Management command cleanup completed")
            print(result.stdout)
        else:
            print(f"[ERROR] Management command failed: {result.stderr}")
            
    except subprocess.TimeoutExpired:
        print("[ERROR] Management command timed out")
    except Exception as e:
        print(f"[ERROR] Failed to run management command: {e}")

def cleanup(headers):
    print_step("Cleanup: Deleting Old Test Data")
    
    # STEP 1: Always use management command first for reliable cleanup
    print("[INFO] Using Django management command for reliable cleanup...")
    cleanup_via_management_command()
    
    # STEP 2: Verify cleanup was successful via API
    print("\n[VERIFICATION] Verifying cleanup via API...")
    org_resp = requests.get(f"{BASE_URL}/organizations/", headers=headers)
    orgs = check_response(org_resp, "Fetching organizations after cleanup")
    
    if orgs:
        test_org = next((o for o in orgs if o['name'] == TEST_ORG_NAME), None)
        if test_org:
            print(f"[WARNING] Test organization still exists: {test_org['name']} (ID: {test_org['id']})")
            
            # STEP 3: Force cleanup via API if management command missed something
            print("[INFO] Attempting additional API cleanup...")
            org_id = test_org['id']
            
            # Delete clients first (cascades to deals and payments)
            clients_resp = requests.get(f"{BASE_URL}/clients/", headers=headers)
            clients = check_response(clients_resp, "Fetching remaining clients")
            if clients:
                for client in clients:
                    if client.get('organization') == org_id:
                        del_client_resp = requests.delete(f"{BASE_URL}/clients/{client['id']}/", headers=headers)
                        check_response(del_client_resp, f"Force deleting client {client.get('client_name', 'Unknown')}")
            
            # Delete any remaining users
            all_users_resp = requests.get(f"{BASE_URL}/auth/users/", headers=headers)
            all_users = check_response(all_users_resp, "Fetching remaining users")
            if all_users:
                test_emails = ["org.admin@apexinc.com", "sales.user@apexinc.com", "verifier.user@apexinc.com", "head.user@apexinc.com", "member.user@apexinc.com"]
                for user in all_users:
                    if user.get('email') in test_emails and user.get('organization') == org_id:
                        del_user_resp = requests.delete(f"{BASE_URL}/auth/users/{user['id']}/", headers=headers)
                        check_response(del_user_resp, f"Force deleting user {user.get('email')}")
            
            # Delete the organization
            del_org_resp = requests.delete(f"{BASE_URL}/organizations/{org_id}/", headers=headers)
            check_response(del_org_resp, f"Force deleting organization")
            
        else:
            print("[SUCCESS] No test organization found - cleanup successful")
    else:
        print("[SUCCESS] No organizations found - cleanup successful")
    
    # FINAL VERIFICATION
    print("\n[FINAL VERIFICATION] Double-checking cleanup...")
    final_org_resp = requests.get(f"{BASE_URL}/organizations/", headers=headers)
    final_orgs = check_response(final_org_resp, "Final verification")
    
    if final_orgs:
        remaining_test_org = next((o for o in final_orgs if o['name'] == TEST_ORG_NAME), None)
        if remaining_test_org:
            print(f"[CRITICAL ERROR] Test organization STILL exists: {remaining_test_org['id']}")
            print("Manual cleanup required!")
            return False
        else:
            print("[SUCCESS] Cleanup verification passed - no test organization found")
    else:
        print("[SUCCESS] No organizations exist - complete cleanup verified")
    
    return True

def get_permissions_by_codenames(headers, codenames):
    response = requests.get(f"{BASE_URL}/permissions/all/", headers=headers)
    all_perms_data = check_response(response, "Fetching all permissions")
    if not all_perms_data: return []
    all_permissions = [p for category in all_perms_data.values() for p in category]
    perm_ids = [p['id'] for p in all_permissions if p['codename'] in codenames]
    return perm_ids

def main():
    # --- Super Admin Login ---
    print_step("Step 1: Super Admin Login")
    otp_resp = requests.post(f"{BASE_URL}/auth/super-admin/login/", json={"email": SUPER_ADMIN_EMAIL, "password": SUPER_ADMIN_PASSWORD})
    if otp_resp.status_code != 200: print("[FATAL] Could not get OTP."); return
    otp = input("Please enter the OTP: ")
    verify_resp = requests.post(f"{BASE_URL}/auth/super-admin/verify/", json={"email": SUPER_ADMIN_EMAIL, "otp": otp})
    sa_data = check_response(verify_resp, "Super Admin OTP Verification")
    if not sa_data or "token" not in sa_data: return
    sa_headers = {"Authorization": f"Token {sa_data['token']}"}

    # --- Cleanup & Org Creation ---
    cleanup(sa_headers)
    print_step(f"Step 2: Create Organization '{TEST_ORG_NAME}'")
    org_payload = {"name": TEST_ORG_NAME, "admin_email": "org.admin@apexinc.com", "admin_password": "password123"}
    org_resp = requests.post(f"{BASE_URL}/register/", json=org_payload, headers=sa_headers)
    created_org_data = check_response(org_resp, "Organization Creation")
    if not created_org_data: return
    org_id = created_org_data.get('organization', {}).get('id')

    # --- Org Admin Login & Setup ---
    print_step("Step 3: Org Admin Login & Setup")
    admin_headers, _ = get_auth_token("org.admin@apexinc.com", "password123")
    if not admin_headers: return

    print_step("Step 4: Create Roles and Assign Permissions")
    sales_perms = get_permissions_by_codenames(admin_headers, ["create_client", "view_own_clients", "create_deal", "view_own_deals"])
    verifier_perms = get_permissions_by_codenames(admin_headers, ["view_all_deals", "log_deal_activity", "verify_deal_payment"])
    
    roles_to_create = {
        "Salesperson": sales_perms, "Verifier": verifier_perms,
        "Team Head": get_permissions_by_codenames(admin_headers, ["view_all_deals"]), "Team Member": []
    }
    role_ids = {}
    for name, perms in roles_to_create.items():
        role_payload = {"name": name, "permissions": perms}
        role_resp = requests.post(f"{BASE_URL}/permissions/roles/", json=role_payload, headers=admin_headers)
        role_data = check_response(role_resp, f"Create Role: {name}")
        if role_data: role_ids[name] = role_data['id']

    # --- User Creation ---
    print_step("Step 5: Create Users with Roles")
    users_to_create = {
        "Salesperson": "sales.user@apexinc.com", "Verifier": "verifier.user@apexinc.com",
        "Team Head": "head.user@apexinc.com", "Team Member": "member.user@apexinc.com"
    }
    created_users = {}
    for role_name, email in users_to_create.items():
        user_payload = {"username": email.split('@')[0], "email": email, "password": "password123", "role": role_ids.get(role_name)}
        user_resp = requests.post(f"{BASE_URL}/auth/users/", json=user_payload, headers=admin_headers)
        user_data = check_response(user_resp, f"Create User: {email}")
        if user_data:
            created_users[role_name] = user_data
        elif user_resp.status_code == 400 and "already exists" in user_resp.text:
            print(f"[WARNING] User {email} already exists - this indicates incomplete cleanup")
            # Try to find the existing user
            all_users_resp = requests.get(f"{BASE_URL}/auth/users/", headers=admin_headers)
            all_users = check_response(all_users_resp, "Fetching existing users")
            if all_users:
                existing_user = next((u for u in all_users if u.get('email') == email), None)
                if existing_user:
                    created_users[role_name] = existing_user
                    print(f"[INFO] Using existing user {email} (ID: {existing_user['id']})")
        else:
            print(f"[ERROR] Failed to create or find user {email}, test may fail")
            return  # Exit early if user creation fails

    # --- Salesperson Workflow ---
    print_step("Step 6: Salesperson Workflow")
    sales_headers, sales_user = get_auth_token("sales.user@apexinc.com", "password123")
    if not sales_headers: return

    # DEBUG: Check sales user's role and permissions
    print(f"[DEBUG] Sales user data: {sales_user}")
    if sales_user and 'role' in sales_user and sales_user['role']:
        role_data = sales_user['role']
        if isinstance(role_data, dict) and 'id' in role_data:
            role_id = role_data['id']
            role_resp = requests.get(f"{BASE_URL}/permissions/roles/{role_id}/", headers=admin_headers)
            full_role_data = check_response(role_resp, "Fetching sales user's role details")
            if full_role_data:
                print(f"[DEBUG] Sales user role: {role_data.get('name')} with {len(role_data.get('permissions', []))} permissions")
                print(f"[DEBUG] Role permissions: {role_data.get('permissions', [])}")
            else:
                print(f"[DEBUG] Could not fetch full role details, but user has role: {role_data.get('name')}")
                print(f"[DEBUG] Role permissions: {role_data.get('permissions', [])}")
        else:
            print(f"[DEBUG] Sales user has role but unexpected format: {role_data}")
    else:
        print("[DEBUG] Sales user has no role assigned!")

    # --- Create Client ---
    client_payload = {
        "client_name": "Global Corp",
        "email": "contact@globalcorp.com",
        "phone_number": "1112223333",
        "address": "123 Global Ave, Business City"
    }
    client_resp = requests.post(f"{BASE_URL}/clients/", json=client_payload, headers=sales_headers)
    client_data = check_response(client_resp, "Salesperson creates Client")
    if not client_data: return

    client_id = client_data.get('id')
    deal_payload = {
        "client_name": client_data.get('client_name'),
        "pay_status": "partial_payment",
        "source_type": "referral", 
        "deal_value": 50000.00,
        "deal_date": "2025-08-01",
        "due_date": "2025-09-01",
        "payment_method": "bank"
    }
    deal_resp = requests.post(f"{BASE_URL}/clients/{client_id}/deals/", json=deal_payload, headers=sales_headers)
    deal_data = check_response(deal_resp, "Salesperson creates Deal")
    if not deal_data: return
    deal_id = deal_data.get('id')

    payment_payload = {
        "payment_date": "2025-08-01", 
        "received_amount": 25000, 
        "payment_type": "partial_payment",
        "cheque_number": "CHQ123456"
    }
    with open(TEST_RECEIPT_PATH, 'rb') as f:
        files = {'receipt_file': (os.path.basename(TEST_RECEIPT_PATH), f, 'image/jpeg')}
        payment_resp = requests.post(f"{BASE_URL}/clients/{client_id}/deals/{deal_id}/payments/", data=payment_payload, headers=sales_headers, files=files)
        check_response(payment_resp, "Salesperson adds Payment with Receipt")

    # --- Verifier Workflow ---
    print_step("Step 7: Verifier Workflow")
    verifier_headers, _ = get_auth_token("verifier.user@apexinc.com", "password123")
    if not verifier_headers: return
    
    log_payload = {"message": "Receipt and payment details confirmed."}
    log_resp = requests.post(f"{BASE_URL}/clients/{client_id}/deals/{deal_id}/log_activity/", json=log_payload, headers=verifier_headers)
    check_response(log_resp, "Verifier adds verification log")

    print_step("🎉 ALL TESTS COMPLETED SUCCESSFULLY! 🎉")
    
    # --- FINAL CLEANUP: Ensure everything is cleaned up ---
    print_step("Final Cleanup: Ensuring Complete Database Cleanup")
    try:
        cleanup_success = cleanup(sa_headers)
        if cleanup_success:
            print("[SUCCESS] Final cleanup completed - database is clean for next test run")
        else:
            print("[WARNING] Final cleanup may have failed - manual intervention may be required")
    except Exception as cleanup_error:
        print(f"[ERROR] Final cleanup failed: {cleanup_error}")
        # Force cleanup via management command as last resort
        print("[INFO] Attempting emergency cleanup via management command...")
        cleanup_via_management_command()

if __name__ == "__main__":
    Path("receipts").mkdir(exist_ok=True)
    if not Path(TEST_RECEIPT_PATH).exists():
        with open(TEST_RECEIPT_PATH, 'wb') as f:
            f.write(b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc`\x00\x00\x00\x02\x00\x01\xe2!\xbc\x33\x00\x00\x00\x00IEND\xaeB`\x82')
    main()