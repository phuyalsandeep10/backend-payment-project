import requests
import json
from datetime import datetime, timedelta

# --- Configuration ---
BASE_URL = "https://payment-rs.onrender.com/api"
SALESPERSON_EMAIL = "sales@innovate.com"
PASSWORD = "password123"

# --- ANSI Color Codes for Rich Output ---
class colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# --- Helper Functions ---
def print_header(title):
    print(f"\n{colors.HEADER}{colors.BOLD}===== {title.upper()} ====={colors.ENDC}")

def print_result(endpoint, method, status_code, expected_status, response_data):
    """Prints the result of a test, indicating pass or fail."""
    if status_code == expected_status:
        status_color = colors.OKGREEN
        result = "[PASS]"
    else:
        status_color = colors.FAIL
        result = "[FAIL]"

    print(f"{colors.OKBLUE}{method:<7}{colors.ENDC} {endpoint:<55} {status_color}{status_code}{colors.ENDC} {result}")
    if result == "[FAIL]":
        print(f"      Expected: {expected_status}, Got: {status_code}")
    if response_data:
        data_str = json.dumps(response_data, indent=2)
        if len(data_str) > 300:
            data_str = data_str[:300] + "..."
        print(f"{colors.OKCYAN}Response:{colors.ENDC}\n{data_str}")

def get_auth_token(email, password):
    """Logs in a user and returns the authentication token."""
    print_header("Authentication")
    url = f"{BASE_URL}/auth/login/"
    data = {"email": email, "password": password}
    token = None
    try:
        response = requests.post(url, json=data)
        result = response.json()
        print_result(url, "POST", response.status_code, 200, result)
        token = result.get("token")
        assert response.status_code == 200 and token, "Authentication failed"
        print(f"{colors.OKGREEN}Successfully authenticated.{colors.ENDC}")
    except (requests.exceptions.RequestException, AssertionError) as e:
        print(f"{colors.FAIL}Authentication failed: {e}{colors.ENDC}")
    return token

def run_test(method, endpoint, headers, expected_status, json_data=None):
    """Runs a generic test for an endpoint and asserts the status code."""
    url = f"{BASE_URL}{endpoint}"
    response_json = None
    try:
        response = requests.request(method, url, headers=headers, json=json_data)
        if response.text:
            try:
                response_json = response.json()
            except json.JSONDecodeError:
                response_json = {"raw_response": response.text[:200]}
        print_result(url, method, response.status_code, expected_status, response_json)
        assert response.status_code == expected_status
    except (requests.exceptions.RequestException, AssertionError) as e:
        print(f"{colors.FAIL}Test failed for {method} {url}: {e}{colors.ENDC}")
    return response_json

# --- Test Cases ---
def test_salesperson_endpoints(token):
    if not token:
        print(f"{colors.FAIL}Authentication failed. Cannot proceed with tests.{colors.ENDC}")
        return

    headers = {"Authorization": f"Token {token}"}
    client_id = None
    deal_id = None

    # --- Dashboard ---
    print_header("Sales Dashboard")
    run_test("GET", "/dashboard/", headers, 200)

    # --- Clients CRUD ---
    print_header("Clients (CRUD)")
    new_client_data = {
        "client_name": f"Test Client {datetime.now().strftime('%Y%m%d%H%M%S')}",
        "email": f"test.client.{datetime.now().strftime('%Y%m%d%H%M%S')}@example.com",
        "phone_number": "1234567890",
        "status": "pending"
    }
    created_client = run_test("POST", "/clients/", headers, 201, json_data=new_client_data)
    if created_client and created_client.get('id'):
        client_id = created_client.get('id')
        assert created_client.get('client_name') == new_client_data['client_name']
        print(f"{colors.OKGREEN}      -> Client creation confirmed.{colors.ENDC}")
        run_test("GET", f"/clients/{client_id}/", headers, 200)
        updated_client = run_test("PATCH", f"/clients/{client_id}/", headers, 200, json_data={"status": "clear"})
        if updated_client:
            assert updated_client.get('status') == 'clear'
            print(f"{colors.OKGREEN}      -> Client update confirmed.{colors.ENDC}")
    
    run_test("GET", "/clients/", headers, 200)

    # --- Deals CRUD ---
    print_header("Deals (CRUD)")
    if client_id:
        new_deal_data = {
            "client_id": client_id,
            "deal_name": f"Test Deal {datetime.now().strftime('%Y%m%d%H%M%S')}",
            "deal_value": "5000.00",
            "deal_date": datetime.now().date().isoformat(),
            "payment_method": "bank",
            "source_type": "referral",
            "payment_status": "initial payment"
        }
        created_deal = run_test("POST", "/deals/deals/", headers, 201, json_data=new_deal_data)
        if created_deal and created_deal.get('deal_id'):
            deal_id = created_deal.get('deal_id')
            assert created_deal.get('deal_name') == new_deal_data['deal_name']
            print(f"{colors.OKGREEN}      -> Deal creation confirmed.{colors.ENDC}")

            run_test("GET", f"/deals/deals/{deal_id}/", headers, 200)
            updated_deal = run_test("PATCH", f"/deals/deals/{deal_id}/", headers, 200, json_data={"deal_value": "5500.00"})
            if updated_deal:
                assert updated_deal.get('deal_value') == '5500.00'
                print(f"{colors.OKGREEN}      -> Deal update confirmed.{colors.ENDC}")

            # run_test("GET", f"/deals/{deal_id}/expand/", headers, 200)
            # run_test("GET", f"/deals/{deal_id}/log-activity/", headers, 200)
            run_test("GET", f"/deals/deals/{deal_id}/expand/", headers, 200)
            run_test("GET", f"/deals/deals/{deal_id}/log-activity/", headers, 200)
    
    run_test("GET", "/deals/", headers, 200)

    # --- Commission ---
    print_header("Commission")
    run_test("GET", "/commission/", headers, 200)

    # --- Team ---
    print_header("Team")
    run_test("GET", "/team/teams/", headers, 200)

    # --- Project ---
    print_header("Project")
    run_test("GET", "/project/projects/", headers, 200)

    # --- Notifications ---
    print_header("Notifications")
    run_test("GET", "/notifications/", headers, 200)
    run_test("GET", "/notifications/notification-settings/", headers, 200)

    # --- User Profile ---
    print_header("User Profile")
    run_test("GET", "/auth/profile/", headers, 200)
    profile_update_data = {
        "profile": {
            "bio": "This is an updated test bio."
        }
    }
    updated_profile_response = run_test("PATCH", "/auth/profile/", headers, 200, json_data=profile_update_data)
    if updated_profile_response:
        assert updated_profile_response.get('profile', {}).get('bio') == "This is an updated test bio."
        print(f"{colors.OKGREEN}      -> User profile update confirmed.{colors.ENDC}")

    # --- NEGATIVE TESTS: Accessing Verifier Endpoints ---
    print_header("Negative Tests (Accessing Verifier Endpoints)")
    run_test("GET", "/verifier/dashboard/", headers, 403)
    run_test("GET", "/verifier/invoices/", headers, 403)

    # --- Cleanup ---
    print_header("Cleanup")
    if deal_id:
        run_test("DELETE", f"/deals/deals/{deal_id}/", headers, 204)
    if client_id:
        run_test("DELETE", f"/clients/{client_id}/", headers, 204)

if __name__ == "__main__":
    sales_token = get_auth_token(SALESPERSON_EMAIL, PASSWORD)
    test_salesperson_endpoints(sales_token) 