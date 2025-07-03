from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.db.models import Sum, Q, Count, Avg
from django.utils import timezone
from django.contrib.auth import get_user_model
from decimal import Decimal
from datetime import datetime, timedelta
from deals.models import Deal, Payment
from clients.models import Client
from commission.models import Commission
from organization.models import Organization
from team.models import Team
from .models import DailyStreakRecord
from .utils import calculate_streaks_for_user_login
from .serializers import (
    DashboardResponseSerializer, DashboardQuerySerializer,
    StreakInfoResponseSerializer, StreakRecalculationRequestSerializer, 
    StreakRecalculationResponseSerializer, StreakLeaderboardResponseSerializer,
    LeaderboardQuerySerializer, StandingsQuerySerializer, StandingsResponseSerializer,
    CommissionQuerySerializer, CommissionOverviewResponseSerializer,
    ClientStatusQuerySerializer, ClientListResponseSerializer
)
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django.db import models

User = get_user_model()

# Create your views here.

# Removed redundant StreakView class - using function-based view with Swagger documentation

# Removed redundant StreakLeaderboardView class - using function-based view with Swagger documentation

# Removed redundant DashboardView class - using function-based view with Swagger documentation

# Removed redundant DailyStandingsView class - using function-based view with Swagger documentation

# Removed redundant CommissionOverviewView class - using function-based view with Swagger documentation

# Removed redundant SalespersonClientListView class - using function-based view with Swagger documentation

@swagger_auto_schema(
    method='get',
    operation_description="Get comprehensive dashboard data including sales progress, streak info, and recent activities",
    query_serializer=DashboardQuerySerializer,
    responses={
        200: DashboardResponseSerializer,
        401: "Unauthorized",
        500: "Internal Server Error"
    },
    manual_parameters=[
        openapi.Parameter(
            'Authorization',
            openapi.IN_HEADER,
            description="Token authentication header (format: 'Token <your_token>')",
            type=openapi.TYPE_STRING,
            required=True,
            default="Token 5df12943f200cc5d1962c461bf480ff763728d95",
            example="Token 5df12943f200cc5d1962c461bf480ff763728d95"
        )
    ],
    tags=['Dashboard']
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def dashboard_view(request):
    """
    Main dashboard endpoint that provides comprehensive sales and performance data.
    Automatically triggers streak calculation for current user.
    """
    try:
        user = request.user
        period = request.GET.get('period', 'monthly')
        include_charts = request.GET.get('include_charts', 'true').lower() == 'true'
        
        # Trigger streak calculation
        try:
            calculate_streaks_for_user_login(user)
        except Exception as e:
            print(f"Warning: Streak calculation failed: {e}")
        
        # Calculate date range based on period
        now = timezone.now()
        if period == 'daily':
            start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
        elif period == 'weekly':
            start_date = now - timedelta(days=now.weekday())
            start_date = start_date.replace(hour=0, minute=0, second=0, microsecond=0)
        elif period == 'yearly':
            start_date = now.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
        else:  # monthly
            start_date = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        
        # Get user deals for the period
        user_deals = Deal.objects.filter(
            created_by=user,
            deal_date__gte=start_date
        )
        
        # Calculate sales progress
        current_sales = user_deals.filter(
            pay_status__in=['verified', 'partial']
        ).aggregate(
            total=Sum('deal_value')
        )['total'] or Decimal('0')
        
        sales_target = user.sales_target or Decimal('25000')
        progress_percentage = float((current_sales / sales_target) * 100) if sales_target > 0 else 0
        
        # Get outstanding deals
        outstanding_deals = Deal.objects.filter(
            created_by=user,
            pay_status='pending'
        ).values(
            'id', 'client_name', 'deal_value', 'deal_date'
        )[:10]
        
        # Get recent payments
        recent_payments = Payment.objects.filter(
            deal__created_by=user
        ).select_related('deal').order_by('-payment_date').values(
            'id', 'deal__client_name', 'received_amount', 'payment_type',
            'receipt_file', 'payment_date'
        )[:10]
        
        # Get verification status summary
        verification_status = user_deals.values('pay_status').annotate(
            count=Count('id'),
            total_value=Sum('deal_value')
        )
        
        status_summary = {
            'verified': {'count': 0, 'total': Decimal('0')},
            'pending': {'count': 0, 'total': Decimal('0')},
            'rejected': {'count': 0, 'total': Decimal('0')},
            'partial': {'count': 0, 'total': Decimal('0')}
        }
        
        for status_data in verification_status:
            status_key = status_data['pay_status']
            if status_key in status_summary:
                status_summary[status_key] = {
                    'count': status_data['count'],
                    'total': status_data['total_value'] or Decimal('0')
                }
        
        # Prepare response data
        response_data = {
            'user_info': {
                'username': user.username,
                'email': user.email,
                'organization': user.organization.name if user.organization else 'No Organization',
                'role': user.role.name if user.role else 'No Role',
                'full_name': f"{user.first_name} {user.last_name}".strip() or user.username
            },
            'sales_progress': {
                'current_sales': str(current_sales),
                'target': str(sales_target),
                'percentage': round(progress_percentage, 2),
                'deals_closed': user_deals.filter(pay_status__in=['verified', 'partial']).count(),
                'deals_pending': user_deals.filter(pay_status='pending').count(),
                'period': period
            },
            'streak_info': {
                'current_streak': user.streak,
                'streak_emoji': get_streak_emoji(user.streak),
                'streak_level': get_streak_level(user.streak),
                'last_updated': timezone.now().date().isoformat()
            },
            'outstanding_deals': list(outstanding_deals),
            'recent_payments': list(recent_payments),
            'verification_status': status_summary
        }
        
        # Add chart data if requested
        if include_charts:
            response_data['chart_data'] = get_chart_data(user, period, start_date, now)
        
        return Response(response_data, status=status.HTTP_200_OK)
        
    except Exception as e:
        return Response(
            {'error': f'Failed to load dashboard: {str(e)}'}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@swagger_auto_schema(
    method='get',
    operation_description="Get detailed streak information including level, history, and statistics",
    responses={
        200: StreakInfoResponseSerializer,
        401: "Unauthorized"
    },
    tags=['Streak']
)
@swagger_auto_schema(
    method='post',
    operation_description="Manually recalculate user's streak with optional parameters",
    request_body=StreakRecalculationRequestSerializer,
    responses={
        200: StreakRecalculationResponseSerializer,
        400: "Bad Request",
        401: "Unauthorized"
    },
    tags=['Streak']
)
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def streak_view(request):
    """
    Handle streak information retrieval and manual recalculation.
    GET: Returns detailed streak information
    POST: Manually recalculates streak with optional parameters
    """
    user = request.user
    
    if request.method == 'GET':
        # Get recent streak history
        recent_records = DailyStreakRecord.objects.filter(
            user=user
        ).order_by('-date')[:30]
        
        # Calculate statistics
        all_records = DailyStreakRecord.objects.filter(user=user)
        # For streak records, we don't store individual streak values, use user's current streak
        longest_streak = user.streak  # Current streak is the best we have
        total_records = all_records.count()
        avg_deals = all_records.aggregate(
            avg=models.Avg('deals_closed')
        )['avg'] or 0
        
        # Get performance insights
        insights = generate_performance_insights(user, recent_records)
        
        response_data = {
            'current_streak': user.streak,
            'streak_emoji': get_streak_emoji(user.streak),
            'streak_level': get_streak_level(user.streak),
            'days_until_next_level': get_days_until_next_level(user.streak),
            'recent_history': [
                {
                    'date': record.date.isoformat(),
                    'deals_closed': record.deals_closed,
                    'total_value': str(record.total_deal_value),
                    'streak_updated': record.streak_updated
                } for record in recent_records
            ],
            'streak_statistics': {
                'longest_streak': longest_streak,
                'total_days_tracked': total_records,
                'average_deals_per_day': round(float(avg_deals), 2)
            },
            'performance_insights': insights
        }
        
        return Response(response_data, status=status.HTTP_200_OK)
    
    elif request.method == 'POST':
        # Manual streak recalculation
        serializer = StreakRecalculationRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        old_streak = user.streak
        force_recalculate = serializer.validated_data.get('force_recalculate', False)
        from_date = serializer.validated_data.get('recalculate_from_date')
        
        try:
            # Perform recalculation
            if from_date:
                # Custom date range recalculation logic here
                calculation_result = calculate_streaks_from_date(user, from_date, force_recalculate)
            else:
                calculation_result = calculate_streaks_for_user_login(user)
            
            # Refresh user data
            user.refresh_from_db()
            new_streak = user.streak
            
            response_data = {
                'message': 'Streak recalculated successfully',
                'old_streak': old_streak,
                'new_streak': new_streak,
                'streak_change': new_streak - old_streak,
                'days_processed': calculation_result.get('days_processed', 0),
                'calculation_details': calculation_result.get('details', [])
            }
            
            return Response(response_data, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response(
                {'error': f'Streak recalculation failed: {str(e)}'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

@swagger_auto_schema(
    method='get',
    operation_description="Get organization-wide streak leaderboard with rankings",
    query_serializer=LeaderboardQuerySerializer,
    responses={
        200: StreakLeaderboardResponseSerializer,
        401: "Unauthorized"
    },
    tags=['Leaderboard']
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def streak_leaderboard_view(request):
    """
    Get organization-wide streak leaderboard.
    """
    limit = int(request.GET.get('limit', 20))
    period = request.GET.get('period', 'current')
    
    # SuperAdmins can view system-wide leaderboard
    if request.user.is_superuser:
        if not request.user.organization:
            # System-wide leaderboard for SuperAdmin
            org_users = User.objects.filter(is_active=True).exclude(is_superuser=True)
            organization_name = "System-wide Leaderboard"
        else:
            org_users = User.objects.filter(organization=request.user.organization, is_active=True)
            organization_name = request.user.organization.name
    else:
        if not request.user.organization:
            return Response(
                {'error': 'User must belong to an organization'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        org_users = User.objects.filter(organization=request.user.organization, is_active=True)
        organization_name = request.user.organization.name
    
    # Calculate sales for period if needed
    now = timezone.now()
    if period == 'monthly':
        start_date = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    elif period == 'quarterly':
        quarter_start = ((now.month - 1) // 3) * 3 + 1
        start_date = now.replace(month=quarter_start, day=1, hour=0, minute=0, second=0, microsecond=0)
    elif period == 'yearly':
        start_date = now.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
    else:
        start_date = None
    
    # Build leaderboard data
    leaderboard_data = []
    for user in org_users:
        # Calculate sales and deals for period
        if start_date:
                    user_deals = Deal.objects.filter(
            created_by=user,
            deal_date__gte=start_date,
            pay_status__in=['verified', 'partial']
        )
        else:
                    user_deals = Deal.objects.filter(
            created_by=user,
            pay_status__in=['verified', 'partial']
        )
        
        sales_total = user_deals.aggregate(total=Sum('deal_value'))['total'] or Decimal('0')
        deals_closed = user_deals.count()
        
        leaderboard_data.append({
            'user_id': user.id,
            'username': user.username,
            'email': user.email,
            'streak': user.streak,
            'streak_emoji': get_streak_emoji(user.streak),
            'sales_total': sales_total,
            'deals_closed': deals_closed,
            'is_current_user': user.id == request.user.id
        })
    
    # Sort by streak (descending)
    leaderboard_data.sort(key=lambda x: x['streak'], reverse=True)
    
    # Add rankings
    for rank, entry in enumerate(leaderboard_data, 1):
        entry['rank'] = rank
        if entry['is_current_user']:
            current_user_rank = rank
    
    # Limit results
    leaderboard_data = leaderboard_data[:limit]
    
    response_data = {
        'organization': organization_name,
        'total_participants': org_users.count(),
        'current_user_rank': locals().get('current_user_rank', 0),
        'leaderboard': leaderboard_data,
        'last_updated': timezone.now()
    }
    
    return Response(response_data, status=status.HTTP_200_OK)

@swagger_auto_schema(
    method='get',
    operation_description="Get daily standings for individuals or teams",
    query_serializer=StandingsQuerySerializer,
    responses={
        200: StandingsResponseSerializer,
        400: "Bad Request",
        401: "Unauthorized"
    },
    tags=['Standings']
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def daily_standings_view(request):
    """
    Get daily standings for individuals or teams.
    """
    serializer = StandingsQuerySerializer(data=request.GET)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    standings_type = serializer.validated_data['type']
    target_date = serializer.validated_data.get('date', timezone.now().date())
    limit = serializer.validated_data['limit']
    
    if standings_type == 'individual':
        standings_data = get_individual_standings(request.user, target_date, limit)
    else:
        standings_data = get_team_standings(request.user, target_date, limit)
    
    return Response(standings_data, status=status.HTTP_200_OK)

@swagger_auto_schema(
    method='get',
    operation_description="Get commission overview with goal progress and top clients",
    query_serializer=CommissionQuerySerializer,
    responses={
        200: CommissionOverviewResponseSerializer,
        401: "Unauthorized"
    },
    tags=['Commission']
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def commission_overview_view(request):
    """
    Get commission overview with organizational goals and user performance.
    """
    serializer = CommissionQuerySerializer(data=request.GET)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    period = serializer.validated_data['period']
    include_details = serializer.validated_data['include_details']
    
    user = request.user
    organization = user.organization
    
    # Calculate date range
    now = timezone.now()
    if period == 'quarterly':
        quarter_start = ((now.month - 1) // 3) * 3 + 1
        start_date = now.replace(month=quarter_start, day=1, hour=0, minute=0, second=0, microsecond=0)
    elif period == 'yearly':
        start_date = now.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
    else:  # monthly
        start_date = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    
    # Handle SuperAdmin without organization - show system-wide data
    if user.is_superuser and not organization:
        org_goal = Decimal('500000')  # System-wide goal
        org_sales = Deal.objects.filter(
            deal_date__gte=start_date,
            pay_status__in=['verified', 'partial']
        ).aggregate(total=Sum('deal_value'))['total'] or Decimal('0')
        total_commissions = Commission.objects.all().aggregate(total=Sum('converted_amount'))['total'] or Decimal('0')
    else:
        # Get organization goal
        org_goal = organization.sales_goal if organization else Decimal('100000')
        
        # Calculate organization progress
        org_sales = Deal.objects.filter(
            created_by__organization=organization,
            deal_date__gte=start_date,
            pay_status__in=['verified', 'partial']
        ).aggregate(total=Sum('deal_value'))['total'] or Decimal('0')
        
        # Get total commissions for organization
        total_commissions = Commission.objects.filter(
            user__organization=organization
        ).aggregate(total=Sum('converted_amount'))['total'] or Decimal('0')
    
    goal_progress = float((org_sales / org_goal) * 100) if org_goal > 0 else 0
    
    # Get user commissions
    user_commissions = Commission.objects.filter(
        user=user
    ).aggregate(total=Sum('converted_amount'))['total'] or Decimal('0')
    

    
    # Get top clients
    top_clients_data = get_top_clients_data(user, start_date, include_details)
    
    response_data = {
        'organization_goal': org_goal,
        'goal_progress': round(goal_progress, 2),
        'user_commissions': user_commissions,
        'total_commissions': total_commissions,
        'top_clients': top_clients_data,
        'commission_trends': get_commission_trends(user, period, start_date) if include_details else [],
        'period_summary': {
            'period': period,
            'start_date': start_date.date().isoformat(),
            'end_date': now.date().isoformat(),
            'organization_sales': str(org_sales)
        }
    }
    
    return Response(response_data, status=status.HTTP_200_OK)

@swagger_auto_schema(
    method='get',
    operation_description="Get client list with payment status information",
    query_serializer=ClientStatusQuerySerializer,
    responses={
        200: ClientListResponseSerializer,
        401: "Unauthorized"
    },
    tags=['Clients']
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def client_list_view(request):
    """
    Get list of clients with their payment status and deal information.
    """
    serializer = ClientStatusQuerySerializer(data=request.GET)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    status_filter = serializer.validated_data['status_filter']
    search = serializer.validated_data.get('search', '')
    limit = serializer.validated_data['limit']
    
    user = request.user
    
    # Get client names from deals created by this user
    user_deal_clients = Deal.objects.filter(
        created_by=user
    ).values_list('client_name', flat=True).distinct()
    
    # Get clients that match those names
    clients_queryset = Client.objects.filter(
        client_name__in=user_deal_clients
    )
    
    # Apply search filter
    if search:
        clients_queryset = clients_queryset.filter(
            Q(client_name__icontains=search) | 
            Q(email__icontains=search)
        )
    
    # Build client data with payment status
    clients_data = []
    status_summary = {
        'all': 0, 'clear': 0, 'pending': 0, 'bad_debt': 0
    }
    
    for client in clients_queryset:
        # Get client's deals with this user
        client_deals = Deal.objects.filter(client_name=client.client_name, created_by=user)
        
        total_value = client_deals.aggregate(
            total=Sum('deal_value')
        )['total'] or Decimal('0')
        
        paid_amount = client_deals.filter(
            pay_status__in=['verified', 'partial']
        ).aggregate(
            total=Sum('deal_value')
        )['total'] or Decimal('0')
        
        outstanding = total_value - paid_amount
        
        # Determine payment status
        if outstanding <= 0:
            payment_status = 'clear'
            status_color = 'green'
        elif outstanding < total_value * Decimal('0.5'):
            payment_status = 'pending'
            status_color = 'yellow'
        else:
            payment_status = 'bad_debt'
            status_color = 'red'
        
        # Get last payment date
        last_payment = Payment.objects.filter(
            deal__client_name=client.client_name,
            deal__created_by=user
        ).order_by('-payment_date').first()
        
        client_info = {
            'client_id': client.id,
            'client_name': client.client_name,
            'email': client.email,
            'phone_number': client.phone_number,
            'total_deals': client_deals.count(),
            'total_value': total_value,
            'paid_amount': paid_amount,
            'outstanding_amount': outstanding,
            'payment_status': payment_status,
            'status_color': status_color,
            'last_payment_date': last_payment.payment_date if last_payment else None,
            'remarks': getattr(client, 'remarks', None)
        }
        
        # Apply status filter
        if status_filter == 'all' or status_filter == payment_status:
            clients_data.append(client_info)
        
        # Update summary
        status_summary['all'] += 1
        status_summary[payment_status] += 1
    
    # Sort and limit
    clients_data.sort(key=lambda x: x['outstanding_amount'], reverse=True)
    clients_data = clients_data[:limit]
    
    response_data = {
        'total_clients': len(clients_data),
        'clients': clients_data,
        'status_summary': status_summary,
        'pagination': {
            'limit': limit,
            'has_more': len(clients_queryset) > limit
        }
    }
    
    return Response(response_data, status=status.HTTP_200_OK)

# ==================== HELPER FUNCTIONS ====================

def get_streak_emoji(streak):
    """Get emoji representation of streak level"""
    if streak >= 50:
        return "🌟🌟🌟🌟🌟"
    elif streak >= 30:
        return "🌟🌟🌟🌟"
    elif streak >= 20:
        return "🌟🌟🌟"
    elif streak >= 10:
        return "⭐⭐⭐"
    elif streak >= 5:
        return "⭐⭐"
    elif streak >= 1:
        return "⭐"
    else:
        return "💤"

def get_streak_level(streak):
    """Get text description of streak level"""
    if streak >= 50:
        return "Sales Legend"
    elif streak >= 30:
        return "Sales Master"
    elif streak >= 20:
        return "Sales Pro"
    elif streak >= 10:
        return "Rising Star"
    elif streak >= 5:
        return "Getting Started"
    elif streak >= 1:
        return "Beginner"
    else:
        return "New"

def get_days_until_next_level(streak):
    """Calculate days until next streak level"""
    levels = [1, 5, 10, 20, 30, 50]
    for level in levels:
        if streak < level:
            return level - streak
    return 0  # Already at max level

def get_chart_data(user, period, start_date, end_date):
    """Generate chart data for dashboard"""
    # Implementation for chart data generation
    return {
        'sales_trend': [],
        'deal_status_distribution': {},
        'commission_trend': []
    }

def generate_performance_insights(user, recent_records):
    """Generate performance insights based on recent streak history"""
    insights = []
    
    if len(recent_records) >= 7:
        recent_week = recent_records[:7]
        avg_deals = sum(r.deals_closed for r in recent_week) / len(recent_week)
        
        if avg_deals >= 2:
            insights.append("Great performance! You're averaging 2+ deals per day.")
        elif avg_deals >= 1:
            insights.append("Good momentum! Keep up the consistent deal closing.")
        else:
            insights.append("Focus on deal conversion to improve your streak.")
    
    if user.streak >= 10:
        insights.append("You're on a hot streak! Maintain this momentum.")
    elif user.streak >= 5:
        insights.append("Building good momentum. Keep pushing!")
    
    return insights

def calculate_streaks_from_date(user, from_date, force_recalculate):
    """Calculate streaks from a specific date"""
    # Implementation for custom date range calculation
    return {
        'days_processed': 0,
        'details': []
    }

def get_individual_standings(user, target_date, limit):
    """Get individual standings for a specific date"""
    # Implementation for individual standings
    return {
        'type': 'individual',
        'date': target_date,
        'total_participants': 0,
        'current_user_rank': 0,
        'standings': [],
        'summary': {}
    }

def get_team_standings(user, target_date, limit):
    """Get team standings for a specific date"""
    # Implementation for team standings
    return {
        'type': 'team',
        'date': target_date,
        'total_participants': 0,
        'current_user_rank': 0,
        'standings': [],
        'summary': {}
    }

def get_top_clients_data(user, start_date, include_details):
    """Get top clients data with deal information"""
    clients_data = []
    
    # Get clients with deals in the period
    client_deals = Deal.objects.filter(
        created_by=user,
        deal_date__gte=start_date,
        pay_status__in=['verified', 'partial']
    ).values('client_name').annotate(
        total_deals=Count('id'),
        total_value=Sum('deal_value')
    ).order_by('-total_value')[:10]
    
    for deal_data in client_deals:
        # Calculate commission earned from this client
        commissions = Commission.objects.filter(
            user=user
        ).aggregate(total=Sum('converted_amount'))['total'] or Decimal('0')
        
        # Get last deal date
        last_deal = Deal.objects.filter(
            created_by=user,
            client_name=deal_data['client_name'],
            deal_date__gte=start_date
        ).order_by('-deal_date').first()
        
        clients_data.append({
            'client_name': deal_data['client_name'],
            'total_deals': deal_data['total_deals'],
            'total_value': deal_data['total_value'],
            'commission_earned': commissions,
            'last_deal_date': last_deal.deal_date if last_deal else None
        })
    
    return clients_data

def get_commission_trends(user, period, start_date):
    """Get commission trend data for charts"""
    # Implementation for commission trends
    return []
