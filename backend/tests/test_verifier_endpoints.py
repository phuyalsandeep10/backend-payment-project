import requests
import json
from datetime import datetime

# --- Configuration ---
BASE_URL = "https://backend-prs.onrender.com/api/v1"
VERIFIER_EMAIL = "verifier@innovate.com"
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

    print(f"{colors.OKBLUE}{method:<7}{colors.ENDC} {endpoint:<65} {status_color}{status_code}{colors.ENDC} {result}")
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

def run_test(method, endpoint, headers, expected_status, json_data=None, data=None):
    """Runs a generic test for an endpoint and asserts the status code."""
    url = f"{BASE_URL}{endpoint}"
    response_json = None
    try:
        if method.upper() == 'POST' and data is not None:
            response = requests.post(url, headers=headers, data=data)
        else:
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
def test_verifier_endpoints(token):
    if not token:
        print(f"{colors.FAIL}Authentication failed. Cannot proceed with tests.{colors.ENDC}")
        return

    headers = {"Authorization": f"Token {token}"}

    # --- Verifier Dashboard ---
    print_header("Verifier Dashboard & Analytics")
    run_test("GET", "/verifier/dashboard/", headers, 200)
    run_test("GET", "/verifier/dashboard/invoice-status/", headers, 200)
    run_test("GET", "/verifier/dashboard/payment-methods/", headers, 200)
    run_test("GET", "/verifier/dashboard/verification-queue/", headers, 200)
    run_test("GET", "/verifier/dashboard/payment-status-distribution/", headers, 200)
    run_test("GET", "/verifier/dashboard/audit-logs/", headers, 200)
    run_test("GET", "/verifier/dashboard/payment-failure-reasons/", headers, 200)
    run_test("GET", "/verifier/dashboard/recent-refunds-or-bad-debts/", headers, 200)

    # --- Invoice Management ---
    print_header("Invoice Management")
    # Test main invoices endpoint with different status filters
    run_test("GET", "/verifier/invoices/", headers, 200)
    run_test("GET", "/verifier/invoices/?status=pending", headers, 200)
    run_test("GET", "/verifier/invoices/?status=verified", headers, 200)
    run_test("GET", "/verifier/invoices/?status=rejected", headers, 200)
    run_test("GET", "/verifier/invoices/?status=refunded", headers, 200)
    run_test("GET", "/verifier/invoices/?status=bad_debt", headers, 200)
    # Test search functionality
    run_test("GET", "/verifier/invoices/?search=INV", headers, 200)

    # --- Payment Verification Workflow ---
    print_header("Payment Verification Workflow")
    # First, find a pending payment to verify using the main invoices endpoint
    pending_invoices = run_test("GET", "/verifier/invoices/?status=pending", headers, 200)
    payment_to_verify_id = None
    invoice_id_to_check = None
    if pending_invoices and isinstance(pending_invoices, list) and len(pending_invoices) > 0:
        payment_to_verify_id = pending_invoices[0].get('payment_id')
        invoice_id_to_check = pending_invoices[0].get('invoice_id')

    if payment_to_verify_id:
        print(f"\n{colors.WARNING}Attempting to verify payment ID: {payment_to_verify_id}{colors.ENDC}")
        run_test("GET", f"/verifier/verifier-form/{payment_to_verify_id}/", headers, 200)
        
        # This data now matches what the UI and the updated backend view expect.
        verification_data = {
            "approved_remarks": "approved",
        }
        run_test("POST", f"/verifier/verifier-form/{payment_to_verify_id}/", headers, 200, data=verification_data)

        # Confirmation check: Verify the invoice is now in 'verified' status
        print(f"\n{colors.WARNING}Confirming verification status for invoice ID: {invoice_id_to_check}{colors.ENDC}")
        verified_invoices = run_test("GET", "/verifier/invoices/?status=verified", headers, 200)
        
        is_verified = verified_invoices and any(inv.get('invoice_id') == invoice_id_to_check for inv in verified_invoices)
        
        if is_verified:
            print(f"{colors.OKGREEN}      -> Verification confirmed. Invoice is now in 'verified' list.{colors.ENDC}")
        else:
            print(f"{colors.FAIL}      -> Verification FAILED. Invoice not found in 'verified' list.{colors.ENDC}")
        
        assert is_verified, f"Invoice {invoice_id_to_check} was not found in the verified list after approval."

    else:
        print(f"{colors.WARNING}No pending payments found to test verification workflow.{colors.ENDC}")

    # --- Deals (Read-only for Verifier) ---
    print_header("Deals (Read-Only)")
    run_test("GET", "/verifier/deals/", headers, 200)

    # --- Shared Endpoints ---
    print_header("Shared Endpoints")
    run_test("GET", "/auth/profile/", headers, 200)
    run_test("GET", "/clients/", headers, 200)

    # --- NEGATIVE TESTS: Accessing Salesperson Endpoints ---
    print_header("Negative Tests (Accessing Salesperson Endpoints)")
    run_test("GET", "/dashboard/dashboard/", headers, 403)
    run_test("GET", "/commission/", headers, 403)
    # Try to create a deal (should fail with 403 due to insufficient permissions)
    run_test("POST", "/deals/deals/", headers, 403, json_data={"client": 1, "deal_name": "Should Fail"})


if __name__ == "__main__":
    verifier_token = get_auth_token(VERIFIER_EMAIL, PASSWORD)
    test_verifier_endpoints(verifier_token) 