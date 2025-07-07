from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from authentication.models import User
from organization.models import Organization
from permissions.models import Role, Permission

class VerifierDashboardSmokeTests(TestCase):
    def setUp(self):
        self.organization = Organization.objects.create(name="Test Org")
        
        self.verifier_role = Role.objects.create(
            name="Verifier",
            organization=self.organization
        )
        
        verifier_permissions = [
            ('view_payment_verification_dashboard', 'Can view payment verification dashboard', 'Verifier'),
            ('verify_payments', 'Can verify payments', 'Verifier'),
            ('view_audit_logs', 'Can view audit logs', 'Verifier'),
        ]
        
        for codename, name, category in verifier_permissions:
            perm, created = Permission.objects.get_or_create(
                codename=codename,
                defaults={'name': name, 'category': category}
            )
            self.verifier_role.permissions.add(perm)

        self.verifier_user = User.objects.create_user(
            email="verifier@example.com",
            username="verifier@example.com",
            password="defaultpass",
            organization=self.organization,
            role=self.verifier_role
        )
        self.client.force_login(self.verifier_user)

    def test_verifier_dashboard_access(self):
        """
        Test that a user with the Verifier role can access the main dashboard.
        """
        url = reverse('verifier_dashboard:verifier_dashboard')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_audit_logs_access(self):
        """
        Test that a user with the Verifier role can access the audit logs.
        """
        url = reverse('verifier_dashboard:audit-logs')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_unauthorized_access(self):
        """
        Test that a user without the correct role cannot access the dashboard.
        """
        unauthorized_user = User.objects.create_user(
            email="unauthorized@example.com",
            username="unauthorized@example.com",
            password="defaultpass",
            organization=self.organization,
        )
        self.client.force_login(unauthorized_user)
        
        url = reverse('verifier_dashboard:verifier_dashboard')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN) 