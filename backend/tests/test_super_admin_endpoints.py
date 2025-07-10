import requests
import json
from datetime import datetime

# Basic color constants for console output
class colors:
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    OKBLUE = '\033[94m'

BASE_URL = "https://backend-prs.onrender.com/api/v1"
SUPER_ADMIN_EMAIL = "super@innovate.com"
SUPER_ADMIN_PASSWORD = "password123"

def print_header(title):
    """Prints a formatted header to the console."""
    print(f"\n{'='*20} {title.upper()} {'='*20}")

def print_result(endpoint, method, status_code, expected_status, response_data):
    """Prints the result of a test, indicating pass or fail."""
    if status_code == expected_status:
        status_color = colors.OKGREEN
        result = "[PASS]"
    else:
        status_color = colors.FAIL
        result = f"[FAIL]"
    
    print(f"{colors.OKBLUE}{method:<7}{colors.ENDC} {endpoint:<65} {status_color}{status_code}{colors.ENDC} {result}")
    
    if result == "[FAIL]":
        print(f"      Expected: {expected_status}, Got: {status_code}")
        if response_data:
            print(f"      Response: {json.dumps(response_data, indent=2)}")
        assert status_code == expected_status, f"Test failed for {method} {endpoint}"

def run_test(method, endpoint, headers, expected_status, json_data=None, params=None):
    """Runs a single API test and prints the result."""
    full_url = f"{BASE_URL}{endpoint}"
    try:
        if method == "GET":
            response = requests.get(full_url, headers=headers, params=params)
        elif method == "POST":
            response = requests.post(full_url, headers=headers, json=json_data)
        elif method == "PATCH":
            response = requests.patch(full_url, headers=headers, json=json_data)
        elif method == "DELETE":
            response = requests.delete(full_url, headers=headers)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")

        response_data = response.json() if response.content else None
        print_result(endpoint, method, response.status_code, expected_status, response_data)
        return response_data
    except requests.exceptions.RequestException as e:
        print(f"{colors.FAIL}Request failed for {method} {full_url}: {e}{colors.ENDC}")
        return None
    except json.JSONDecodeError:
        print_result(endpoint, method, response.status_code, expected_status, "Invalid JSON response")
        return None

def authenticate(email, password):
    """Authenticates a user and returns the token."""
    print_header("Authentication")
    auth_data = {"email": email, "password": password}
    response_data = run_test("POST", "/auth/login/", {}, 200, json_data=auth_data)
    if response_data and response_data.get("token"):
        print(f"{colors.OKGREEN}Successfully authenticated.{colors.ENDC}")
        return {"Authorization": f"Token {response_data['token']}"}
    else:
        print(f"{colors.FAIL}Authentication failed.{colors.ENDC}")
        exit(1)

def get_organization_id(headers, name="Innovate Inc."):
    """Fetches the ID for a named organization."""
    print_header(f"Fetching Organization ID for '{name}'")
    # This is a simplification; in a real-world scenario, you might list orgs and find the one you need
    # For now, we'll rely on the existing endpoint for the default org.
    if name == "Innovate Inc.":
        response_data = run_test("GET", "/organizations/get-innovate-id/", headers, 200)
        if response_data and response_data.get("id"):
            org_id = response_data["id"]
            print(f"{colors.OKGREEN}      -> Found Organization ID: {org_id}{colors.ENDC}")
            return org_id
    # If we need another org's ID, we would need a more robust endpoint
    print(f"{colors.FAIL}Could not fetch Organization ID for '{name}'.{colors.ENDC}")
    exit(1)

def get_role_id(headers, role_name="Salesperson", org_id=None):
    """Fetches the ID for a given role in the specified organization."""
    print_header(f"Fetching {role_name} Role ID")
    
    # For Super Admins, we need to specify the organization
    params = None
    if org_id:
        params = {"organization": org_id}
    
    if role_name == "Salesperson":
        response_data = run_test("GET", "/permissions/get-salesperson-id/", headers, 200, params=params)
        if response_data and response_data.get("id"):
            role_id = response_data["id"]
            print(f"{colors.OKGREEN}      -> Found {role_name} Role ID: {role_id}{colors.ENDC}")
            return role_id
    print(f"{colors.FAIL}Could not fetch {role_name} Role ID.{colors.ENDC}")
    exit(1)

def test_super_admin_endpoints(headers):
    """Runs all tests for Super Admin endpoints."""
    # --- ORGANIZATION MANAGEMENT (Super Admin creates org + admin) ---
    print_header("Organization Management (Super Admin creates org + admin)")
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    new_org_data = {
        "name": f"New Org {timestamp}",
        "description": "A test org created by Super Admin",
        "admin_email": f"orgadmin_{timestamp}@example.com",
        "admin_first_name": "Org",
        "admin_last_name": "Admin",
        "admin_password": "password1234"
    }
    created = run_test("POST", "/organizations/create_with_admin/", headers, 201, json_data=new_org_data)
    if created and created.get('organization') and created.get('admin_user'):
        org_id = created['organization']['id']
        org_admin_email = created['admin_user']['email']
        print(f"{colors.OKGREEN}      -> Organization and Org Admin creation confirmed.{colors.ENDC}")
    else:
        print(f"{colors.FAIL}Organization and Org Admin creation failed.{colors.ENDC}")
        exit(1)

    # --- USER MANAGEMENT (Full CRUD) ---
    print_header("User Management (CRUD)")
    sales_role_id = get_role_id(headers, "Salesperson", org_id)
    new_user_data = {
        "username": f"newuser_{timestamp}",
        "email": f"new.user.{timestamp}@example.com",
        "first_name": "Test",
        "last_name": "User",
        "password": "password123",
        "role": sales_role_id,
        "organization": org_id
    }
    created_user = run_test("POST", "/auth/users/", headers, 201, json_data=new_user_data)
    
    if created_user and created_user.get('id'):
        user_id = created_user.get('id')
        print(f"{colors.OKGREEN}      -> User creation confirmed.{colors.ENDC}")
        run_test("GET", f"/auth/users/{user_id}/", headers, 200)
        run_test("PATCH", f"/auth/users/{user_id}/", headers, 200, json_data={"first_name": "Updated"})
        run_test("DELETE", f"/auth/users/{user_id}/", headers, 204)
        print(f"{colors.OKGREEN}      -> User update and delete confirmed.{colors.ENDC}")

    # --- POSITIVE ACCESS TESTS ---
    print_header("Positive Access Tests")
    run_test("GET", "/dashboard/dashboard/", headers, 200)
    run_test("GET", "/verifier/dashboard/", headers, 200)


if __name__ == "__main__":
    print("Attempting to run Super Admin tests...")
    
    super_admin_token = authenticate(SUPER_ADMIN_EMAIL, SUPER_ADMIN_PASSWORD)
    test_super_admin_endpoints(super_admin_token)

    print(f"\n{colors.OKGREEN}Super Admin tests completed.{colors.ENDC}") 