import pytest
from rest_framework.test import APIClient
from rest_framework.authtoken.models import Token
from django.contrib.auth import get_user_model


@pytest.mark.django_db
def test_sales_dashboard_aliases():
    """Ensure dashboard alias endpoints respond successfully."""
    User = get_user_model()
    user = User.objects.create_user(email="alias@test.com", password="strong-pass")
    token = Token.objects.create(user=user)

    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")

    paths = [
        "/api/dashboard/",
        "/api/dashboard/streaks/",
        "/api/dashboard/chart/",
        "/api/dashboard/goals/",
        "/api/dashboard/payment-verification/",
    ]

    for p in paths:
        res = client.get(p)
        assert res.status_code == 200, f"{p} returned {res.status_code}" 