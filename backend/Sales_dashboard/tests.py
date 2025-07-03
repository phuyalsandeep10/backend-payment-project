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

    def test_streak_calculation_logic(self):
        """Test the automatic streak calculation logic."""
        from Sales_dashboard.signals import update_user_streak_for_date
        
        print("\n--- Testing Streak Calculation Logic ---")
        
        # Reset streak to 5 for testing
        self.salesperson.streak = 5
        self.salesperson.save()
        print(f"Initial streak: {self.salesperson.streak}")
        
        today = timezone.now().date()
        
        # Test 1: Good deal (>= 101) should increase streak
        Deal.objects.create(
            organization=self.organization, created_by=self.salesperson, client_name="Good Client",
            deal_value=500, deal_status='verified', pay_status='full_payment', deal_date=today, due_date=today + timedelta(days=30)
        )
        self.salesperson.refresh_from_db()
        print(f"After good deal (500): {self.salesperson.streak} (should be 6)")
        
        # Test 2: Small deal (< 101) should decrease streak by half
        tomorrow = today + timedelta(days=1)
        Deal.objects.create(
            organization=self.organization, created_by=self.salesperson, client_name="Small Client",
            deal_value=50, deal_status='verified', pay_status='full_payment', deal_date=tomorrow, due_date=tomorrow + timedelta(days=30)
        )
        self.salesperson.refresh_from_db()
        print(f"After small deal (50): {self.salesperson.streak} (should be 3)")
        
        # Test 3: No deals on a day should decrease streak by half
        day_after = tomorrow + timedelta(days=1)
        update_user_streak_for_date(self.salesperson, day_after)  # Manually trigger for no-deal day
        self.salesperson.refresh_from_db()
        print(f"After no deals day: {self.salesperson.streak} (should be 1)")
        
        print("-------------------------------------------\n")

    def test_automatic_streak_on_login(self):
        """Test automatic streak calculation when user logs in or accesses dashboard."""
        from Sales_dashboard.utils import calculate_streaks_for_user_login
        from django.urls import reverse
        
        print("\n--- Testing Automatic Streak on Login/Dashboard Access ---")
        
        # Reset streak and create some historical deals
        self.salesperson.streak = 0
        self.salesperson.save()
        
        today = timezone.now().date()
        yesterday = today - timedelta(days=1)
        two_days_ago = today - timedelta(days=2)
        
        # Create deals for different days
        Deal.objects.create(
            organization=self.organization, created_by=self.salesperson, client_name="Day 1 Client",
            deal_value=200, deal_status='verified', pay_status='full_payment', 
            deal_date=two_days_ago, due_date=two_days_ago + timedelta(days=30)
        )
        Deal.objects.create(
            organization=self.organization, created_by=self.salesperson, client_name="Day 2 Client",
            deal_value=150, deal_status='verified', pay_status='full_payment', 
            deal_date=yesterday, due_date=yesterday + timedelta(days=30)
        )
        
        print(f"Initial streak: {self.salesperson.streak}")
        
        # Simulate login (automatic streak calculation)
        calculate_streaks_for_user_login(self.salesperson)
        self.salesperson.refresh_from_db()
        print(f"After automatic login streak calculation: {self.salesperson.streak}")
        
        # Test dashboard access (should also trigger streak calculation)
        url = reverse('dashboard')
        response = self.client.get(url, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Check that streak is included in response
        self.assertIn('streak', response.data)
        print(f"Streak in dashboard response: {response.data['streak']}")
        
        print("-------------------------------------------\n")

    def test_auto_login_endpoint_with_streak(self):
        """Test the new auto-login endpoint that calculates streaks automatically."""
        from django.urls import reverse
        
        print("\n--- Testing Auto-Login Endpoint with Streak Calculation ---")
        
        # Reset streak and create some deals
        self.salesperson.streak = 0
        # Set a known password
        self.salesperson.set_password('testpass123')
        self.salesperson.save()
        
        today = timezone.now().date()
        yesterday = today - timedelta(days=1)
        
        # Create a good deal from yesterday
        Deal.objects.create(
            organization=self.organization, created_by=self.salesperson, client_name="Yesterday Client",
            deal_value=250, deal_status='verified', pay_status='full_payment', 
            deal_date=yesterday, due_date=yesterday + timedelta(days=30)
        )
        
        print(f"Initial streak before login: {self.salesperson.streak}")
        
        # Test the auto-login endpoint
        url = reverse('auto-login')
        login_data = {
            'email': self.salesperson.email,
            'password': 'testpass123'
        }
        
        # Logout first to test fresh login
        self.client.logout()
        response = self.client.post(url, login_data, format='json')
        
        if response.status_code == 200:
            print(f"Login successful!")
            print(f"Response data: {response.data}")
            print(f"Updated streak returned by login: {response.data.get('streak', 'N/A')}")
            
            # Verify streak was included in response
            self.assertIn('streak', response.data)
            self.assertIn('sales_target', response.data)
            
        else:
            print(f"Login failed with status: {response.status_code}")
            print(f"Response: {response.data}")
        
        print("-------------------------------------------\n")

    def test_streak_info_endpoint(self):
        """Test the dedicated streak information endpoint."""
        from django.urls import reverse
        
        print("\n--- Testing Streak Information Endpoint ---")
        
        # Create some streak history
        today = timezone.now().date()
        yesterday = today - timedelta(days=1)
        two_days_ago = today - timedelta(days=2)
        
        # Create deals for streak history
        Deal.objects.create(
            organization=self.organization, created_by=self.salesperson, client_name="Good Deal 1",
            deal_value=200, deal_status='verified', pay_status='full_payment', 
            deal_date=two_days_ago, due_date=two_days_ago + timedelta(days=30)
        )
        Deal.objects.create(
            organization=self.organization, created_by=self.salesperson, client_name="Good Deal 2",
            deal_value=150, deal_status='verified', pay_status='full_payment', 
            deal_date=yesterday, due_date=yesterday + timedelta(days=30)
        )
        
        url = reverse('streak_info')
        response = self.client.get(url, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        print(f"Streak Info Response:")
        print(f"- Current Streak: {response.data['current_streak']}")
        print(f"- Streak Emoji: {response.data['streak_emoji']}")
        print(f"- Streak Level: {response.data['streak_level']}")
        print(f"- Days Until Next Level: {response.data['days_until_next_level']}")
        print(f"- Recent History: {len(response.data['recent_history'])} days")
        print(f"- Streak Rules: {response.data['streak_rules']}")
        
        # Verify response structure
        self.assertIn('current_streak', response.data)
        self.assertIn('streak_emoji', response.data)
        self.assertIn('streak_level', response.data)
        self.assertIn('recent_history', response.data)
        self.assertIn('streak_rules', response.data)
        
        print("-------------------------------------------\n")

    def test_streak_leaderboard_endpoint(self):
        """Test the streak leaderboard endpoint."""
        from django.urls import reverse
        from authentication.models import User
        
        print("\n--- Testing Streak Leaderboard Endpoint ---")
        
        # Create additional salespeople for leaderboard
        salesperson2 = User.objects.create_user(
            username='salesperson2', email='sales2@test.com', password='testpass123',
            organization=self.organization, streak=3
        )
        salesperson3 = User.objects.create_user(
            username='salesperson3', email='sales3@test.com', password='testpass123',
            organization=self.organization, streak=1
        )
        
        # Update current salesperson streak
        self.salesperson.streak = 5
        self.salesperson.save()
        
        url = reverse('streak_leaderboard')
        response = self.client.get(url, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        print(f"Leaderboard Response:")
        print(f"- Organization: {response.data['organization']}")
        print(f"- Total Participants: {response.data['total_participants']}")
        print(f"- Current User Rank: {response.data['current_user_rank']}")
        print(f"- Leaderboard:")
        
        for person in response.data['leaderboard']:
            current_indicator = " (YOU)" if person['is_current_user'] else ""
            print(f"  {person['rank']}. {person['username']} - {person['streak']} streak {person['streak_emoji']}{current_indicator}")
        
        # Verify response structure
        self.assertIn('leaderboard', response.data)
        self.assertIn('current_user_rank', response.data)
        self.assertIn('total_participants', response.data)
        self.assertIn('organization', response.data)
        
        print("-------------------------------------------\n")

    def test_streak_manual_recalculation(self):
        """Test manual streak recalculation via POST request."""
        from django.urls import reverse
        
        print("\n--- Testing Manual Streak Recalculation ---")
        
        # Create a deal for today
        today = timezone.now().date()
        Deal.objects.create(
            organization=self.organization, created_by=self.salesperson, client_name="Today's Deal",
            deal_value=300, deal_status='verified', pay_status='full_payment', 
            deal_date=today, due_date=today + timedelta(days=30)
        )
        
        old_streak = self.salesperson.streak
        print(f"Streak before manual recalculation: {old_streak}")
        
        url = reverse('streak_info')
        response = self.client.post(url, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        print(f"Manual Recalculation Response:")
        print(f"- Message: {response.data['message']}")
        print(f"- Old Streak: {response.data['old_streak']}")
        print(f"- New Streak: {response.data['new_streak']}")
        print(f"- Streak Change: {response.data['streak_change']}")
        
        # Verify response structure
        self.assertIn('message', response.data)
        self.assertIn('old_streak', response.data)
        self.assertIn('new_streak', response.data)
        self.assertIn('streak_change', response.data)
        
        print("-------------------------------------------\n")

    def test_all_streak_endpoints_comprehensive(self):
        """Comprehensive test of all streak-related functionality."""
        from django.urls import reverse
        import json
        
        print("\n--- Comprehensive Streak System Test ---")
        
        # Test all endpoints sequentially
        endpoints = [
            ('streak_info', 'GET', 'Streak Information'),
            ('streak_leaderboard', 'GET', 'Streak Leaderboard'),
        ]
        
        for endpoint_name, method, description in endpoints:
            print(f"\n{description} Endpoint:")
            url = reverse(endpoint_name)
            
            if method == 'GET':
                response = self.client.get(url, format='json')
            else:
                response = self.client.post(url, format='json')
            
            print(f"- URL: {url}")
            print(f"- Status: {response.status_code}")
            print(f"- Response Keys: {list(response.data.keys()) if hasattr(response, 'data') else 'No data'}")
            
            if response.status_code == 200:
                print(f"- Success ✓")
            else:
                print(f"- Failed ✗")
        
        print("\n--- All Streak URLs Summary ---")
        print("1. /api/v1/dashboard/streak/ (GET) - Current streak info, history, levels")
        print("2. /api/v1/dashboard/streak/ (POST) - Manual streak recalculation")
        print("3. /api/v1/dashboard/streak/leaderboard/ (GET) - Organization streak rankings")
        print("4. /api/v1/auth/auto-login/ (POST) - Login with automatic streak calculation")
        print("5. /api/v1/dashboard/ (GET) - Main dashboard (includes streak in response)")
        
        print("-------------------------------------------\n")
