import pytest
from rest_framework.test import APIClient
from rest_framework.authtoken.models import Token
from django.contrib.auth import get_user_model


@pytest.mark.django_db
def test_verifier_alias_endpoints():
    User = get_user_model()
    user = User.objects.create_user(email="verifier@test.com", password="password123")
    token = Token.objects.create(user=user)

    # Assign dummy organization attribute if needed
    from organization.models import Organization
    org = Organization.objects.create(name="Test Org", domain="test.org")
    user.organization = org
    user.save(update_fields=["organization"])

    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")

    paths = [
        "/api/verifier/overview/",
        "/api/verifier/payments/",
        "/api/verifier/refunds/",
        "/api/verifier/audits/",
        "/api/verifier/payment-distribution/",
    ]

    for p in paths:
        res = client.get(p)
        # Allow 200 or 204 (no content) for list endpoints
        assert res.status_code in (200, 204), f"{p} returned {res.status_code}" 