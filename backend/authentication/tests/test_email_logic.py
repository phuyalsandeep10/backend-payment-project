from django.test import TestCase, override_settings
from django.urls import reverse
from django.core import mail
from django.contrib.auth import get_user_model
from permissions.models import Role
from organization.models import Organization

User = get_user_model()

SUPER_ADMIN_EMAIL = "super@innovate.com"
ORG_ADMIN_EMAIL = "orgadmin@innovate.com"
PASSWORD = "password123"

@override_settings(EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend')
class TestOTPEmailSending(TestCase):
    def setUp(self):
        # Create organization
        self.organization = Organization.objects.create(
            name="Test Organization",
            description="Test organization for email tests"
        )
        
        # Create super admin user
        self.super_admin = User.objects.create_user(
            email=SUPER_ADMIN_EMAIL,
            password=PASSWORD,
            username="superadmin",
            is_superuser=True,
            is_staff=True,
            organization=self.organization
        )
        
        # Create org admin role and user
        self.org_admin_role, _ = Role.objects.get_or_create(
            name="Org Admin",
            organization=self.organization
        )
        
        self.org_admin = User.objects.create_user(
            email=ORG_ADMIN_EMAIL,
            password=PASSWORD,
            username="orgadmin",
            organization=self.organization,
            role=self.org_admin_role
        )
        
        # Clear any emails that might have been sent during setup
        mail.outbox.clear()

    def test_super_admin_otp_email_sent(self):
        url = reverse('authentication:super_admin_login')
        data = {"email": SUPER_ADMIN_EMAIL, "password": PASSWORD}
        response = self.client.post(url, data, content_type='application/json')
        self.assertEqual(response.status_code, 200)
        resp_json = response.json()
        self.assertIn("OTP sent", resp_json.get("message", ""))
        self.assertTrue(resp_json.get("requires_otp"))
        
        # Check outbox
        self.assertTrue(mail.outbox)
        email_obj = mail.outbox[-1]
        self.assertIn(SUPER_ADMIN_EMAIL, email_obj.to)
        self.assertIn("verification code", email_obj.subject.lower())

    def test_org_admin_otp_email_sent(self):
        url = reverse('authentication:org_admin_login')
        data = {"email": ORG_ADMIN_EMAIL, "password": PASSWORD}
        response = self.client.post(url, data, content_type='application/json')
        self.assertEqual(response.status_code, 200)
        resp_json = response.json()
        self.assertIn("OTP sent", resp_json.get("message", ""))
        self.assertTrue(resp_json.get("requires_otp"))
        
        # Check outbox
        self.assertTrue(mail.outbox)
        email_obj = mail.outbox[-1]
        self.assertIn(ORG_ADMIN_EMAIL, email_obj.to)
        self.assertIn("verification code", email_obj.subject.lower())