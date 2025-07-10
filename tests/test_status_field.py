import pytest
from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model


@pytest.mark.django_db
def test_user_status_pending():
    User = get_user_model()
    user = User.objects.create_user(email="pending@test.com", password="secret", status="pending")
    assert user.status == "pending" 