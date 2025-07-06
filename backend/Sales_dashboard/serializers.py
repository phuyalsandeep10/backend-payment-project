from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import DailyStreakRecord
from deals.models import Deal
from clients.models import Client
from commission.models import Commission
from decimal import Decimal

User = get_user_model()

# ==================== CONSTANTS ====================
LEADERBOARD_PERIOD_CHOICES = ['current', 'monthly', 'quarterly', 'yearly']
CLIENT_STATUS_CHOICES = ['all', 'clear', 'pending', 'bad_debt']
DASHBOARD_PERIOD_CHOICES = ['daily', 'weekly', 'monthly', 'yearly']
STANDINGS_TYPE_CHOICES = ['individual', 'team']
COMMISSION_PERIOD_CHOICES = ['monthly', 'weekly', 'daily']

# ==================== DASHBOARD SERIALIZERS ====================

class OutstandingDealSerializer(serializers.Serializer):
    """Serializer for outstanding deal information"""
    id = serializers.IntegerField(help_text="Deal ID")
    client_name = serializers.CharField(help_text="Client name")
    deal_value = serializers.DecimalField(max_digits=15, decimal_places=2, help_text="Deal value")
    deal_date = serializers.DateField(help_text="Deal date")
    client_satisfaction = serializers.ChoiceField(
        choices=[('neutral', 'Neutral'), ('satisfied', 'Satisfied'), ('unsatisfied', 'Un-Satisfied')],
        allow_null=True,
        help_text="Client satisfaction level"
    )
    client_status = serializers.ChoiceField(
        choices=[('pending', 'Pending'), ('bad_debt', 'Bad Debt'), ('clear', 'Clear')],
        allow_null=True,
        help_text="Client payment status"
    )

class DashboardResponseSerializer(serializers.Serializer):
    """Serializer for main dashboard response"""
    user_info = serializers.DictField(help_text="Current user information")
    sales_progress = serializers.DictField(help_text="Sales progress data")
    streak_info = serializers.DictField(help_text="Current streak information, including rating")
    outstanding_deals = OutstandingDealSerializer(many=True, help_text="List of outstanding deals with client satisfaction")
    recent_payments = serializers.ListField(help_text="Recent payment activities")
    verification_status = serializers.DictField(help_text="Payment verification status")
    
    class Meta:
        examples = {
            "user_info": {
                "username": "john_doe",
                "email": "john@company.com",
                "organization": "Tech Corp",
                "role": "Salesperson"
            },
            "sales_progress": {
                "current_month_sales": "15000.00",
                "target": "25000.00",
                "percentage": 60.0,
                "deals_closed": 8
            },
            "streak_info": {
                "current_streak": 7.5,
                "streak_rating": "Rising Star"
            },
            "outstanding_deals": [
                {
                    "id": 123,
                    "client_name": "ABC Corp",
                    "deal_value": "5000.00",
                    "deal_date": "2024-01-15",
                    "client_satisfaction": "satisfied",
                    "client_status": "pending"
                }
            ]
        }

class DashboardQuerySerializer(serializers.Serializer):
    """Serializer for dashboard query parameters"""
    period = serializers.ChoiceField(
        choices=DASHBOARD_PERIOD_CHOICES,
        default='monthly',
        help_text="Time period for data aggregation"
    )
    include_charts = serializers.BooleanField(
        default=True,
        help_text="Include chart data in response"
    )

# ==================== STREAK SERIALIZERS ====================

class StreakInfoResponseSerializer(serializers.Serializer):
    """Serializer for streak information response"""
    current_streak = serializers.FloatField(help_text="Current streak value (can be a decimal for half-progress)")
    streak_rating = serializers.CharField(help_text="Text description of streak level")
    days_until_next_level = serializers.IntegerField(help_text="Days needed to reach next level")
    recent_history = serializers.ListField(
        child=serializers.DictField(),
        help_text="Recent daily streak history"
    )
    streak_statistics = serializers.DictField(help_text="Overall streak statistics")
    performance_insights = serializers.ListField(
        child=serializers.CharField(),
        help_text="Performance insights and tips"
    )
    
    class Meta:
        examples = {
            "current_streak": 7,
            "streak_emoji": "⭐⭐⭐",
            "streak_level": "Rising Star",
            "days_until_next_level": 3,
            "recent_history": [
                {
                    "date": "2024-01-15",
                    "deals_closed": 2,
                    "total_value": "500.00",
                    "streak_updated": True
                }
            ],
            "streak_statistics": {
                "longest_streak": 15,
                "total_streaks": 45,
                "average_streak": 6.2
            }
        }

class StreakRecalculationRequestSerializer(serializers.Serializer):
    """Serializer for manual streak recalculation request"""
    force_recalculate = serializers.BooleanField(
        default=False,
        help_text="Force recalculation even if already calculated for today"
    )
    recalculate_from_date = serializers.DateField(
        required=False,
        help_text="Recalculate from specific date (YYYY-MM-DD)"
    )

class StreakRecalculationResponseSerializer(serializers.Serializer):
    """Serializer for streak recalculation response"""
    message = serializers.CharField(help_text="Result message")
    old_streak = serializers.IntegerField(help_text="Previous streak value")
    new_streak = serializers.IntegerField(help_text="Updated streak value")
    streak_change = serializers.IntegerField(help_text="Change in streak (+/-)")
    days_processed = serializers.IntegerField(help_text="Number of days processed")
    calculation_details = serializers.ListField(
        child=serializers.DictField(),
        help_text="Detailed calculation steps"
    )

# ==================== LEADERBOARD SERIALIZERS ====================

class LeaderboardEntrySerializer(serializers.Serializer):
    """Serializer for individual leaderboard entry"""
    rank = serializers.IntegerField(help_text="Current rank")
    user_id = serializers.IntegerField(help_text="User ID")
    username = serializers.CharField(help_text="Username")
    email = serializers.EmailField(help_text="User email")
    streak = serializers.FloatField(help_text="Current streak value")
    streak_rating = serializers.CharField(help_text="Text-based streak rating")
    sales_total = serializers.DecimalField(max_digits=15, decimal_places=2, help_text="Total sales amount")
    deals_closed = serializers.IntegerField(help_text="Number of deals closed")
    is_current_user = serializers.BooleanField(help_text="Whether this is the requesting user")

class StreakLeaderboardResponseSerializer(serializers.Serializer):
    """Serializer for streak leaderboard response"""
    organization = serializers.CharField(help_text="Organization name")
    total_participants = serializers.IntegerField(help_text="Total number of participants")
    current_user_rank = serializers.IntegerField(help_text="Current user's rank")
    leaderboard = LeaderboardEntrySerializer(many=True, help_text="Leaderboard entries")
    last_updated = serializers.DateTimeField(help_text="Last update timestamp")
    
    class Meta:
        examples = {
            "organization": "Tech Corp",
            "total_participants": 25,
            "current_user_rank": 8,
            "leaderboard": [
                {
                    "rank": 1,
                    "username": "top_seller",
                    "streak": 15.0,
                    "streak_rating": "Rising Star",
                    "sales_total": "45000.00",
                    "is_current_user": False
                }
            ]
        }

class LeaderboardQuerySerializer(serializers.Serializer):
    """Serializer for leaderboard query parameters"""
    limit = serializers.IntegerField(
        default=20,
        min_value=5,
        max_value=100,
        help_text="Number of entries to return"
    )
    period = serializers.ChoiceField(
        choices=LEADERBOARD_PERIOD_CHOICES,
        default='current',
        help_text="Time period for leaderboard"
    )

# ==================== STANDINGS SERIALIZERS ====================

class StandingsQuerySerializer(serializers.Serializer):
    """Serializer for daily standings query parameters"""
    type = serializers.ChoiceField(
        choices=STANDINGS_TYPE_CHOICES,
        default='individual',
        help_text="Type of standings to retrieve"
    )
    date = serializers.DateField(
        required=False,
        help_text="Specific date for standings (YYYY-MM-DD)"
    )
    limit = serializers.IntegerField(
        default=10,
        min_value=5,
        max_value=50,
        help_text="Number of standings to return"
    )

class IndividualStandingSerializer(serializers.Serializer):
    """Serializer for individual standing entry"""
    rank = serializers.IntegerField()
    user_id = serializers.IntegerField()
    username = serializers.CharField()
    profile_picture = serializers.URLField(allow_null=True)
    sales_amount = serializers.DecimalField(max_digits=15, decimal_places=2)
    deals_count = serializers.IntegerField()
    streak = serializers.FloatField(help_text="Current streak value")
    performance_score = serializers.FloatField()
    is_current_user = serializers.BooleanField()

class TeamStandingSerializer(serializers.Serializer):
    """Serializer for team standing entry"""
    rank = serializers.IntegerField()
    team_id = serializers.IntegerField()
    team_name = serializers.CharField()
    team_lead_profile_picture = serializers.URLField(allow_null=True)
    total_sales = serializers.DecimalField(max_digits=15, decimal_places=2)
    team_deals = serializers.IntegerField()
    avg_streak = serializers.FloatField()
    member_count = serializers.IntegerField()
    is_user_team = serializers.BooleanField()

class StandingsResponseSerializer(serializers.Serializer):
    """Serializer for standings response"""
    type = serializers.CharField(help_text="Type of standings")
    date = serializers.DateField(help_text="Date of standings")
    total_participants = serializers.IntegerField(help_text="Total participants")
    current_user_rank = serializers.IntegerField(help_text="Current user rank", allow_null=True)
    standings = serializers.ListField(help_text="List of standings")
    summary = serializers.DictField(help_text="Summary statistics")

# ==================== COMMISSION OVERVIEW SERIALIZERS ====================

class CommissionQuerySerializer(serializers.Serializer):
    """Serializer for commission overview query parameters"""
    period = serializers.ChoiceField(
        choices=COMMISSION_PERIOD_CHOICES,
        default='monthly',
        help_text="Period for commission data"
    )
    include_details = serializers.BooleanField(
        default=True,
        help_text="Include detailed commission breakdown"
    )

class TopClientSerializer(serializers.Serializer):
    """Serializer for top client data"""
    client_id = serializers.IntegerField()
    client_name = serializers.CharField()
    total_deals = serializers.IntegerField()
    total_value = serializers.DecimalField(max_digits=15, decimal_places=2)
    commission_earned = serializers.DecimalField(max_digits=15, decimal_places=2)
    last_deal_date = serializers.DateField()

class CompanyGoalChartSerializer(serializers.Serializer):
    """Serializer for the company goal chart data"""
    company_goal = serializers.DecimalField(max_digits=15, decimal_places=2)
    achieved_percentage = serializers.FloatField()
    sales_growth_percentage = serializers.FloatField()
    current_sales = serializers.DecimalField(max_digits=15, decimal_places=2)
    previous_period_sales = serializers.DecimalField(max_digits=15, decimal_places=2)
    summary_message = serializers.CharField()
    subtitle = serializers.CharField()

class CommissionOverviewResponseSerializer(serializers.Serializer):
    """Serializer for commission overview response"""
    organization_goal = serializers.DecimalField(max_digits=15, decimal_places=2)
    goal_progress = serializers.FloatField(help_text="Overall organization goal completion percentage")
    user_commissions = serializers.DecimalField(max_digits=15, decimal_places=2)
    total_commissions = serializers.DecimalField(max_digits=15, decimal_places=2, help_text="Total commissions for the organization")
    company_goal_chart = CompanyGoalChartSerializer(help_text="Data for the company goal progress chart")
    top_clients_this_period = TopClientSerializer(many=True, help_text="Top clients for the selected period.")
    regular_clients_all_time = TopClientSerializer(many=True, help_text="Top 5 all-time regular clients based on sales value.")
    commission_trends = serializers.ListField(
        child=serializers.DictField(),
        help_text="Commission trend data for charts."
    )
    period_summary = serializers.DictField(help_text="Period summary statistics")

# ==================== CLIENT LIST SERIALIZERS ====================

class ClientStatusQuerySerializer(serializers.Serializer):
    """Serializer for client list query parameters"""
    status_filter = serializers.ChoiceField(
        choices=CLIENT_STATUS_CHOICES,
        default='all',
        help_text="Filter clients by payment status"
    )
    search = serializers.CharField(
        required=False,
        help_text="Search clients by name or email"
    )
    limit = serializers.IntegerField(
        default=20,
        min_value=5,
        max_value=100,
        help_text="Number of clients to return"
    )

class ClientStatusSerializer(serializers.Serializer):
    """Serializer for client status information"""
    client_id = serializers.IntegerField()
    client_name = serializers.CharField()
    email = serializers.EmailField()
    phone_number = serializers.CharField()
    total_deals = serializers.IntegerField()
    total_value = serializers.DecimalField(max_digits=15, decimal_places=2)
    paid_amount = serializers.DecimalField(max_digits=15, decimal_places=2)
    outstanding_amount = serializers.DecimalField(max_digits=15, decimal_places=2)
    payment_status = serializers.CharField()
    status_color = serializers.CharField()
    last_payment_date = serializers.DateField(allow_null=True)
    remarks = serializers.CharField(allow_null=True)

class ClientListResponseSerializer(serializers.Serializer):
    """Serializer for client list response"""
    total_clients = serializers.IntegerField()
    clients = ClientStatusSerializer(many=True)
    status_summary = serializers.DictField(help_text="Summary by status")
    pagination = serializers.DictField(help_text="Pagination information") 