from rest_framework import serializers
from deals.models import Deal
from authentication.models import User
from team.models import Team

class SalesTargetSerializer(serializers.ModelSerializer):
    """
    Serializer for the user's sales target and current progress.
    """
    class Meta:
        model = User
        fields = ('sales_target',)

class PaymentVerificationStatusSerializer(serializers.Serializer):
    """
    Aggregates deal amounts by their verification status.
    """
    cleared_amount = serializers.DecimalField(max_digits=15, decimal_places=2)
    not_verified_amount = serializers.DecimalField(max_digits=15, decimal_places=2)
    rejected_amount = serializers.DecimalField(max_digits=15, decimal_places=2)

class OutstandingDealSerializer(serializers.ModelSerializer):
    """
    Lists deals with outstanding payments.
    """
    class Meta:
        model = Deal
        fields = ('client_name', 'deal_id', 'deal_value')

class DailyStandingsSerializer(serializers.Serializer):
    """
    Represents the daily performance of an individual or a team.
    """
    name = serializers.CharField(max_length=255)
    amount = serializers.DecimalField(max_digits=15, decimal_places=2)
    
class TimeSeriesDataPointSerializer(serializers.Serializer):
    """
    Represents a single data point in a time series.
    """
    date = serializers.CharField()
    amount = serializers.DecimalField(max_digits=15, decimal_places=2)


class DashboardSerializer(serializers.Serializer):
    """
    Consolidates all data for the main dashboard view.
    """
    sales_target = serializers.DecimalField(max_digits=15, decimal_places=2, source='user.sales_target')
    current_sales = serializers.DecimalField(max_digits=15, decimal_places=2)
    streak = serializers.IntegerField(source='user.streak')
    payment_verification_status = PaymentVerificationStatusSerializer()
    outstanding_deals = OutstandingDealSerializer(many=True)
    payment_verification_graph = TimeSeriesDataPointSerializer(many=True)

class CompanyGoalSerializer(serializers.Serializer):
    """
    Represents the company's sales goal and current progress.
    """
    sales_goal = serializers.DecimalField(max_digits=15, decimal_places=2)
    current_sales = serializers.DecimalField(max_digits=15, decimal_places=2)
    percentage_achieved = serializers.FloatField()
    monthly_growth = serializers.FloatField()

class TopClientSerializer(serializers.Serializer):
    """
    Represents a top client with their total sales.
    """
    client_name = serializers.CharField()
    total_sales = serializers.DecimalField(max_digits=15, decimal_places=2)

class CommissionOverviewSerializer(serializers.Serializer):
    """
    Consolidates all data for the commission overview page.
    """
    company_goal = CompanyGoalSerializer()
    top_clients = TopClientSerializer(many=True)
    regular_clients = TopClientSerializer(many=True)

class SalespersonClientSerializer(serializers.Serializer):
    """
    Detailed view of a client for the salesperson's list.
    """
    client_name = serializers.CharField()
    total_sales = serializers.DecimalField(max_digits=15, decimal_places=2)
    status = serializers.CharField()
    remarks = serializers.CharField() 