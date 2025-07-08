from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from authentication.models import User
from organization.models import Organization

class SalesDashboardSmokeTests(TestCase):
    def setUp(self):
        self.organization = Organization.objects.create(name="Test Corp")
        self.user = User.objects.create_user(
            email="sales@example.com",
            username="sales@example.com",
            password="defaultpass",
            organization=self.organization,
        )
        self.client.force_login(self.user)

    def test_commission_overview_view_access(self):
        """
        Test that a logged-in user can access the commission overview page.
        """
        url = reverse('sales_dashboard:commission')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_dashboard_view_access(self):
        """
        Test that a logged-in user can access the main dashboard view.
        """
        url = reverse('sales_dashboard:dashboard')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_sales_target_is_zero(self):
        """
        Test that the sales target is 0 if it's set to 0.
        """
        self.user.sales_target = 0
        self.user.save()

        url = reverse('sales_dashboard:dashboard')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['sales_progress']['target'], '0.00')

    def test_sales_target_is_none(self):
        """
        Test that the sales target defaults to 25000 if it's None.
        """
        self.user.sales_target = None
        self.user.save()

        url = reverse('sales_dashboard:dashboard')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['sales_progress']['target'], '25000') 