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

BASE_URL = "https://payment-rs.onrender.com/api"
ORG_ADMIN_EMAIL = "orgadmin@innovate.com"
ORG_ADMIN_PASSWORD = "password123"

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
    """Authenticates a user with email, password, and OTP, returning the token."""
    print_header("Authentication")
    auth_data = {"email": email, "password": password}
    response_data = run_test("POST", "/auth/login/", {}, 200, json_data=auth_data)
    
    if response_data and response_data.get("requires_otp"):
        print(f"{colors.OKBLUE}OTP sent to console or email. Please check and enter the OTP below.{colors.ENDC}")
        otp = input("Enter OTP: ").strip()
        
        # Verify OTP
        otp_data = {"email": email, "otp": otp}
        otp_response = run_test("POST", "/auth/login/verify-otp/", {}, 200, json_data=otp_data)
        
        if otp_response and otp_response.get("token"):
            print(f"{colors.OKGREEN}Successfully authenticated with OTP.{colors.ENDC}")
            return {"Authorization": f"Token {otp_response['token']}"}
        else:
            print(f"{colors.FAIL}OTP verification failed.{colors.ENDC}")
            exit(1)
    else:
        print(f"{colors.FAIL}Authentication failed: No OTP session received.{colors.ENDC}")
        exit(1)


def get_organization_id(headers):
    """Fetches the ID for the 'Innovate Inc.' organization."""
    print_header("Fetching Organization ID")
    response_data = run_test("GET", "/organizations/get-innovate-id/", headers, 200)
    if response_data and response_data.get("id"):
        org_id = response_data["id"]
        print(f"{colors.OKGREEN}      -> Found Organization ID: {org_id}{colors.ENDC}")
        return org_id
    else:
        print(f"{colors.FAIL}Could not fetch Organization ID.{colors.ENDC}")
        exit(1)

def get_salesperson_role_id(headers):
    """Fetches the ID for the 'Salesperson' role."""
    print_header("Fetching Salesperson Role ID")
    response_data = run_test("GET", "/permissions/get-salesperson-id/", headers, 200)
    if response_data and response_data.get("id"):
        role_id = response_data["id"]
        print(f"{colors.OKGREEN}      -> Found Salesperson Role ID: {role_id}{colors.ENDC}")
        return role_id
    else:
        print(f"{colors.FAIL}Could not fetch Salesperson Role ID.{colors.ENDC}")
        exit(1)

def test_org_admin_endpoints(headers):
    """Runs all tests for Organization Admin endpoints."""

    # --- SETUP: Get dynamic IDs ---
    org_id = get_organization_id(headers)
    sales_role_id = get_salesperson_role_id(headers)

    # --- USER MANAGEMENT (Full CRUD) ---
    print_header("User Management (CRUD)")
    new_user_data = {
        "username": f"newuser_{datetime.now().strftime('%Y%m%d%H%M%S')}",
        "email": f"new.user.{datetime.now().strftime('%Y%m%d%H%M%S')}@example.com",
        "first_name": "Test",
        "last_name": "User",
        "password": "password123",
        "role": sales_role_id,
        "organization": org_id
    }
    created_user = run_test("POST", "/auth/users/", headers, 201, json_data=new_user_data)
    
    team_lead_id = None
    if created_user and created_user.get('id'):
        user_id = created_user.get('id')
        team_lead_id = user_id  # Use this dynamically created user as the team lead
        print(f"{colors.OKGREEN}      -> User creation confirmed.{colors.ENDC}")
        run_test("GET", f"/auth/users/{user_id}/", headers, 200)
        run_test("PATCH", f"/auth/users/{user_id}/", headers, 200, json_data={"first_name": "Updated"})
        # Note: Deletion is deferred until after the team tests are complete.
        print(f"{colors.OKGREEN}      -> User read and update confirmed.{colors.ENDC}")

    # --- TEAM MANAGEMENT (Full CRUD) ---
    print_header("Team Management (CRUD)")
    
    if not team_lead_id:
        print(f"{colors.FAIL}Skipping Team Management tests because user creation failed.{colors.ENDC}")
    else:
        new_team_data = { "name": "New Test Team", "team_lead": team_lead_id, "organization": org_id }
        created_team = run_test("POST", "/team/teams/", headers, 201, json_data=new_team_data)
        
        if created_team and created_team.get('id'):
            team_id = created_team.get('id')
            print(f"{colors.OKGREEN}      -> Team creation confirmed.{colors.ENDC}")
            run_test("GET", f"/team/teams/{team_id}/", headers, 200)
            run_test("PATCH", f"/team/teams/{team_id}/", headers, 200, json_data={"description": "Updated team description."})
            run_test("DELETE", f"/team/teams/{team_id}/", headers, 204)
            print(f"{colors.OKGREEN}      -> Team update and delete confirmed.{colors.ENDC}")

        # --- USER CLEANUP ---
        # Now that the team tests are done, we can delete the user.
        print_header("User Cleanup")
        run_test("DELETE", f"/auth/users/{team_lead_id}/", headers, 204)
        print(f"{colors.OKGREEN}      -> Test user deleted successfully.{colors.ENDC}")

    # --- NEGATIVE TESTS ---
    print_header("Negative Tests")
    # Should not be able to access Sales Dashboard
    run_test("GET", "/dashboard/", headers, 403)
    # Should not be able to access Verifier Dashboard
    run_test("GET", "/verifier/dashboard/", headers, 403)
    # Should not be able to create a deal with invalid data (should fail with 400 due to missing required fields)
    run_test("POST", "/deals/deals/", headers, 400, json_data={
        "client_id": 1, "deal_name": "Illegal Deal", "deal_value": "100", "payment_status": "initial payment"
    })


if __name__ == "__main__":
    # Note: This test assumes an 'Organization Admin' user exists with the specified credentials.
    # The initialize_app command needs to be modified to create this user first.
    # Since that failed, this script will likely fail at authentication.
    print("Attempting to run Org Admin tests...")
    print(f"{colors.WARNING}NOTE: This test requires an 'Organization Admin' user with email 'orgadmin@innovate.com'.{colors.ENDC}")
    print(f"{colors.WARNING}Make sure this user has been created by the `initialize_app` command.{colors.ENDC}")
    
    org_admin_token = authenticate(ORG_ADMIN_EMAIL, ORG_ADMIN_PASSWORD)
    test_org_admin_endpoints(org_admin_token)

    print(f"\n{colors.OKGREEN}Organization Admin tests completed.{colors.ENDC}") 