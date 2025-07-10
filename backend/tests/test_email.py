import pytest
import requests

BASE_URL = "http://127.0.0.1:8000/api"
SUPER_ADMIN_EMAIL = "super@innovate.com"
ORG_ADMIN_EMAIL = "orgadmin@innovate.com"
PASSWORD = "password123"

@pytest.mark.parametrize("endpoint,email", [
    ("/auth/login/super-admin/", SUPER_ADMIN_EMAIL),
    ("/auth/login/org-admin/", ORG_ADMIN_EMAIL),
])
def test_otp_email_sent(endpoint, email):
    url = f"{BASE_URL}{endpoint}"
    data = {"email": email, "password": PASSWORD}
    response = requests.post(url, json=data)
    assert response.status_code == 200
    resp_json = response.json()
    assert resp_json.get("message") == "OTP sent"
    assert resp_json.get("requires_otp") is True

    # Fetch the outbox from the test endpoint
    outbox_url = f"{BASE_URL}/auth/test-email-outbox/"
    outbox_response = requests.get(outbox_url)
    assert outbox_response.status_code == 200
    outbox = outbox_response.json().get("outbox", [])
    # Find an email sent to the correct recipient
    found = False
    for email_obj in outbox:
        if email in email_obj["to"] and (
            "verification code" in email_obj["subject"].lower() or
            "verification code" in email_obj["body"].lower()
        ):
            found = True
            break
    assert found, f"No OTP email sent to {email} in outbox!" 