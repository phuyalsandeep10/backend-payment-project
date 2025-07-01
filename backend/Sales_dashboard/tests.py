from django.test import TestCase
import json
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase, APIClient
from django.utils import timezone
from datetime import timedelta
from authentication.models import User
from organization.models import Organization
from deals.models import Deal
from team.models import Team

# Create your tests here.

class DashboardAPITest(APITestCase):

    def setUp(self):
        """Set up the necessary data for the tests."""
        self.organization = Organization.objects.create(name="Test Corp")
        self.salesperson = User.objects.create_user(
            username="salesperson",
            email="sales@test.com",
            password="password123",
            organization=self.organization,
            sales_target=25000.00,
            streak=3
        )
        self.other_salesperson = User.objects.create_user(
            username="other_salesperson",
            email="other@test.com",
            password="password123",
            organization=self.organization
        )

        self.team = Team.objects.create(name="Sales Wizards", organization=self.organization)
        self.team.members.add(self.salesperson)

        today = timezone.now().date()
        last_month = today - timedelta(days=30)
        due_date = today + timedelta(days=30)
        overdue_date = today - timedelta(days=1)

        self.organization.sales_goal = 50000.00
        self.organization.save()

        # Create deals for the main salesperson
        Deal.objects.create(
            organization=self.organization, created_by=self.salesperson, client_name="Client A",
            deal_value=5000, deal_status='verified', pay_status='full_payment', deal_date=today, due_date=due_date
        )
        Deal.objects.create(
            organization=self.organization, created_by=self.salesperson, client_name="Client B",
            deal_value=3000, deal_status='pending', pay_status='full_payment', deal_date=today, due_date=due_date
        )
        Deal.objects.create(
            organization=self.organization, created_by=self.salesperson, client_name="Client C",
            deal_value=10000, deal_status='verified', pay_status='partial_payment', deal_date=last_month, due_date=due_date
        )
        Deal.objects.create(
            organization=self.organization, created_by=self.salesperson, client_name="Client D",
            deal_value=2000, deal_status='rejected', pay_status='full_payment', deal_date=today, due_date=due_date
        )
        # Add an overdue deal to test "Bad Debt" status
        Deal.objects.create(
            organization=self.organization, created_by=self.salesperson, client_name="Client F",
            deal_value=4000, deal_status='verified', pay_status='partial_payment', deal_date=last_month, due_date=overdue_date
        )

        # Create a deal for the other salesperson for standings
        Deal.objects.create(
            organization=self.organization, created_by=self.other_salesperson, client_name="Client E",
            deal_value=7000, deal_status='verified', pay_status='full_payment', deal_date=today, due_date=due_date
        )

        self.client = APIClient()
        self.client.force_authenticate(user=self.salesperson)
        
    def test_dashboard_api(self):
        """Test the main dashboard endpoint and print the results."""
        url = reverse('dashboard')
        response = self.client.get(url, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        print("\n--- Main Dashboard API Response ---")
        print(json.dumps(response.json(), indent=4))
        print("---------------------------------\n")

    def test_individual_standings_api(self):
        """Test the individual daily standings endpoint and print the results."""
        url = reverse('daily-standings')
        response = self.client.get(url + '?type=individual', format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)

        print("\n--- Individual Standings API Response ---")
        print(json.dumps(response.json(), indent=4))
        print("---------------------------------------\n")

    def test_team_standings_api(self):
        """Test the team daily standings endpoint and print the results."""
        url = reverse('daily-standings')
        response = self.client.get(url + '?type=team', format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        print("\n--- Team Standings API Response ---")
        print(json.dumps(response.json(), indent=4))
        print("---------------------------------\n")

    def test_commission_overview_api(self):
        """Test the commission overview endpoint and print the results."""
        url = reverse('commission-overview')
        response = self.client.get(url, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        print("\n--- Commission Overview API Response ---")
        print(json.dumps(response.json(), indent=4))
        print("--------------------------------------\n")

    def test_salesperson_client_list_api(self):
        """Test the salesperson client list endpoint and print the results."""
        url = reverse('client-list')
        response = self.client.get(url, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        print("\n--- Salesperson Client List API Response ---")
        print(json.dumps(response.json(), indent=4))
        print("-------------------------------------------\n")
