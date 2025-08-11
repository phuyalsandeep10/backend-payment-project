from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.db.models import Sum, Q, Count, Avg, Max
from django.db.models.functions import TruncDay, TruncWeek, TruncMonth
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
from .utils import calculate_streaks_for_user_login, calculate_streaks_from_date
from authentication.models import UserProfile
from .serializers import (
    DashboardResponseSerializer, DashboardQuerySerializer,
    StreakInfoResponseSerializer, StreakRecalculationRequestSerializer, 
    StreakRecalculationResponseSerializer, StreakLeaderboardResponseSerializer,
    LeaderboardQuerySerializer, StandingsQuerySerializer, StandingsResponseSerializer,
    CommissionQuerySerializer, CommissionOverviewResponseSerializer,
    ClientStatusQuerySerializer, ClientListResponseSerializer,
    TeamStandingSerializer, IndividualStandingSerializer
)
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django.db import models
import logging
from .permissions import IsSalesperson

User = get_user_model()
logger = logging.getLogger(__name__)


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
            required=True
        )
    ],
    tags=['Dashboard']
)
@api_view(['GET'])
@permission_classes([IsSalesperson])
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
            # Force recalculation from 7 days ago to ensure streak data is always fresh for testing
            seven_days_ago = timezone.now().date() - timedelta(days=7)
            calculate_streaks_from_date(user, from_date=seven_days_ago, force_recalculate=True)
            user.refresh_from_db()  # Refresh user object to get the updated streak
        except Exception as e:
            logger.warning(f"Warning: Streak calculation failed: {e}")
        
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
            verification_status='verified'
        ).aggregate(
            total=Sum('deal_value')
        )['total'] or Decimal('0')
        
        sales_target = user.sales_target if user.sales_target is not None else Decimal('25000')
        progress_percentage = float((current_sales / sales_target) * 100) if sales_target > 0 else 0
        
        # Get outstanding deals
        outstanding_deals_qs = Deal.objects.filter(
            created_by=user,
            verification_status='pending'
        ).select_related('client').order_by('-deal_date')[:10]

        outstanding_deals = []
        for deal in outstanding_deals_qs:
            outstanding_deals.append({
                'id': deal.id,
                'client_name': deal.client.client_name if deal.client else "N/A",
                'deal_value': deal.deal_value,
                'deal_date': deal.deal_date,
                'client_satisfaction': deal.client.satisfaction if deal.client else None,
                'client_status': deal.client.status if deal.client else None
            })
        
        # Get recent payments
        recent_payments_qs = Payment.objects.filter(
            deal__created_by=user
        ).select_related('deal', 'deal__client').order_by('-payment_date')[:10]

        recent_payments = []
        for p in recent_payments_qs:
            client_name = "N/A"
            if p.deal and p.deal.client:
                client_name = p.deal.client.client_name
            
            recent_payments.append({
                'id': p.id,
                'client_name': client_name,
                'received_amount': p.received_amount,
                'payment_type': p.payment_type,
                'receipt_file': p.receipt_file.url if p.receipt_file else None,
                'payment_date': p.payment_date
            })
        
        # Get verification status summary
        verification_status = user_deals.values('verification_status').annotate(
            count=Count('id'),
            total_value=Sum('deal_value')
        )
        
        status_summary = {
            'verified': {'count': 0, 'total': 0.0},
            'pending': {'count': 0, 'total': 0.0},
            'rejected': {'count': 0, 'total': 0.0},
        }
        
        for status_data in verification_status:
            status_key = status_data['verification_status']
            if status_key in status_summary:
                status_summary[status_key] = {
                    'count': status_data['count'],
                    'total': float(status_data['total_value'] or Decimal('0'))
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
                'deals_closed': user_deals.filter(verification_status='verified').count(),
                'deals_pending': user_deals.filter(verification_status='pending').count(),
                'period': period
            },
            'streak_info': {
                'current_streak': user.streak,
                'streak_rating': get_streak_level(user.streak),
                'last_updated': timezone.now().date().isoformat()
            },
            'outstanding_deals': outstanding_deals,
            'recent_payments': recent_payments,
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
            'streak_rating': get_streak_level(user.streak),
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
            verification_status__in=['verified', 'partial']
        )
        else:
                    user_deals = Deal.objects.filter(
            created_by=user,
            verification_status__in=['verified', 'partial']
        )
        
        sales_total = user_deals.aggregate(total=Sum('deal_value'))['total'] or Decimal('0')
        deals_closed = user_deals.count()
        
        leaderboard_data.append({
            'user_id': user.id,
            'username': user.username,
            'email': user.email,
            'streak': user.streak,
            'streak_rating': get_streak_level(user.streak),
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
    operation_description="Get daily, weekly, or monthly standings for individuals or teams",
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
def standings_view(request):
    """
    Get daily, weekly, or monthly standings for individuals or teams.
    """
    user = request.user
    logger.info(f"Standings request for user: {user.username}")

    if not user.organization:
        logger.error(f"User {user.username} does not belong to an organization.")
        return Response(
            {'error': 'User does not belong to an organization.'},
            status=status.HTTP_400_BAD_REQUEST
        )

    # Validate query parameters
    serializer = StandingsQuerySerializer(data=request.GET)
    if not serializer.is_valid():
        logger.error(f"Invalid query parameters for standings: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    validated_data = serializer.validated_data
    standings_type = validated_data.get('type', 'individual')
    period = validated_data.get('period', 'daily')
    limit = validated_data.get('limit', 10)
    logger.info(f"Standings parameters: type={standings_type}, period={period}, limit={limit}")

    # Determine date range based on period
    now = timezone.now()
    if period == 'weekly':
        start_date = (now - timedelta(days=now.weekday())).date()
        end_date = start_date + timedelta(days=6)
    elif period == 'monthly':
        start_date = now.date().replace(day=1)
        end_date = (start_date + timedelta(days=32)).replace(day=1) - timedelta(days=1)
    else: # daily
        start_date = now.date()
        end_date = start_date
    logger.info(f"Date range for standings: {start_date} to {end_date}")

    try:
        if standings_type == 'team':
            logger.info("Fetching team standings.")
            standings_data, total_participants, current_user_rank = get_team_standings(user, start_date, end_date, limit, request)
            serializer_class = TeamStandingSerializer
        else:
            logger.info("Fetching individual standings.")
            standings_data, total_participants, current_user_rank = get_individual_standings(user, start_date, end_date, limit, request)
            serializer_class = IndividualStandingSerializer

        logger.info(f"Standings data retrieved: {len(standings_data)} entries.")

        try:
            standings_serializer = serializer_class(standings_data, many=True)
            serialized_standings = standings_serializer.data
        except Exception as e:
            logger.exception(f"Error serializing standings data: {e}")
            return Response({'error': 'Failed to serialize standings data.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        response_data = {
            'type': standings_type,
            'date': end_date,
            'total_participants': total_participants,
            'current_user_rank': current_user_rank,
            'standings': serialized_standings,
            'summary': {
                'top_performer_sales': standings_data[0]['sales_amount'] if standings_data else 0,
            }
        }
        
        logger.info("Successfully serialized standings data.")
        return Response(StandingsResponseSerializer(response_data).data, status=status.HTTP_200_OK)

    except Exception as e:
        logger.exception("Error fetching standings")  # Use logger.exception to include traceback
        return Response({'error': 'Failed to fetch standings.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

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
    Provides a comprehensive overview of sales commissions, goal progress,
    and top-performing clients based on a specified period.
    """
    try:
        user = request.user
        organization = user.organization
        period = request.GET.get('period', 'monthly')
        include_details = request.GET.get('include_details', 'true').lower() == 'true'

        if not organization:
            if not user.is_superadmin:
                return Response(
                    {'error': 'User is not associated with an organization.'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            # Handle SuperAdmin case separately if needed, or return empty data
            return Response({}, status=status.HTTP_200_OK)


        now = timezone.now()
        if period == 'daily':
            start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
        elif period == 'weekly':
            start_date = (now - timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
        else:  # 'monthly' is the default
            start_date = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

        # Calculate commissions for the organization within the period
        org_commissions = Commission.objects.filter(
            organization=organization,
            created_at__gte=start_date
        )
        
        total_commissions = org_commissions.aggregate(Sum('converted_amount'))['converted_amount__sum'] or Decimal('0')
        
        # Get user-specific commissions
        user_commissions = org_commissions.filter(user=user).aggregate(Sum('converted_amount'))['converted_amount__sum'] or Decimal('0')

        # Organization goal progress
        organization_goal = organization.sales_goal or Decimal('100000') # Default goal
        org_sales = Deal.objects.filter(
            created_by__organization=organization,
            deal_date__gte=start_date,
            verification_status__in=['verified', 'partial']
        ).aggregate(Sum('deal_value'))['deal_value__sum'] or Decimal('0')
        
        goal_progress = (org_sales / organization_goal) * 100 if organization_goal > 0 else 0

        # Get top clients for the period
        top_clients_data = get_top_clients_data(user, start_date, include_details)

        # Get commission trends
        commission_trends = get_commission_trends(user, period, start_date)

        # ==================== COMPANY GOAL CHART ====================
        # User's sales in the current period
        user_sales_current = Deal.objects.filter(
            created_by=user,
            deal_date__gte=start_date,
            verification_status__in=['verified', 'partial']
        ).aggregate(Sum('deal_value'))['deal_value__sum'] or Decimal('0')

        # Calculate previous period for comparison
        if period == 'daily':
            prev_start_date = start_date - timedelta(days=1)
            prev_end_date = start_date
        elif period == 'weekly':
            prev_start_date = start_date - timedelta(weeks=1)
            prev_end_date = start_date
        else:  # 'monthly'
            prev_month_end = start_date.replace(day=1) - timedelta(days=1)
            prev_start_date = prev_month_end.replace(day=1)
            prev_end_date = start_date

        user_sales_previous = Deal.objects.filter(
            created_by=user,
            deal_date__gte=prev_start_date,
            deal_date__lt=prev_end_date,
            verification_status__in=['verified', 'partial']
        ).aggregate(Sum('deal_value'))['deal_value__sum'] or Decimal('0')

        # Calculate sales growth percentage
        if user_sales_previous > 0:
            sales_growth_percentage = ((user_sales_current - user_sales_previous) / user_sales_previous) * 100
        else:
            sales_growth_percentage = 100.0 if user_sales_current > 0 else 0.0

        # Calculate achieved percentage of company goal
        achieved_percentage = (user_sales_current / organization_goal) * 100 if organization_goal > 0 else 0
        
        # Dynamic summary message
        comparison_text = "higher" if sales_growth_percentage >= 0 else "lower"
        summary_message = (
            f"You've done sales of ${user_sales_current:,.0f}, which is "
            f"{abs(sales_growth_percentage):.1f}% {comparison_text} than last {period.replace('ly', '')}. "
            "Keep up the good work."
        )

        company_goal_chart = {
            'company_goal': organization_goal,
            'achieved_percentage': round(float(achieved_percentage), 1),
            'sales_growth_percentage': round(float(sales_growth_percentage), 1),
            'current_sales': user_sales_current,
            'previous_period_sales': user_sales_previous,
            'summary_message': summary_message,
            'subtitle': "Little bit more now."
        }


        response_data = {
            'organization_goal': organization_goal,
            'goal_progress': round(float(goal_progress), 2),
            'user_commissions': user_commissions,
            'total_commissions': total_commissions,
            'company_goal_chart': company_goal_chart,
            'top_clients_this_period': top_clients_data,
            'commission_trends': commission_trends,
            'period_summary': {
                'period': period,
                'start_date': start_date.date().isoformat(),
                'end_date': now.date().isoformat(),
                'organization_sales': str(org_sales)
            },
            'regular_clients_all_time': get_all_time_top_clients_data(user),
        }
        
        return Response(response_data, status=status.HTTP_200_OK)
        
    except Exception as e:
        return Response(
            {'error': f'Failed to load commission overview: {str(e)}'}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
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
    
    # Get client ids from deals created by this user
    user_deal_clients_ids = Deal.objects.filter(
        created_by=user
    ).values_list('client_id', flat=True).distinct()
    
    # Get clients that match those IDs
    clients_queryset = Client.objects.filter(
        id__in=user_deal_clients_ids
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
        client_deals = Deal.objects.filter(client=client, created_by=user)
        
        total_value = client_deals.aggregate(
            total=Sum('deal_value')
        )['total'] or Decimal('0')
        
        paid_amount = client_deals.filter(
            verification_status__in=['verified', 'partial']
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
            deal__client=client,
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
    """
    Generate data for various charts based on the selected period.
    This includes sales trends and payment verification status.
    """
    # 1. Payment Verification Status Chart (Verified Totals)
    if period == 'monthly':
        trunc_period = TruncMonth
        date_format = "%b"  # e.g., 'Jan', 'Feb'
    elif period == 'weekly':
        trunc_period = TruncWeek
        date_format = "W%U" # e.g., 'W34', 'W35'
    else:  # daily
        trunc_period = TruncDay
        date_format = "%Y-%m-%d"

    verified_deals = Deal.objects.filter(
        created_by=user,
        deal_date__gte=start_date,
        deal_date__lte=end_date,
        verification_status='verified'
    ).annotate(
        period_start=trunc_period('deal_date')
    ).values('period_start').annotate(
        total_verified=Sum('deal_value')
    ).order_by('period_start')

    payment_verification_trend = [
        {
            'label': item['period_start'].strftime(date_format),
            'value': item['total_verified']
        }
        for item in verified_deals
    ]

    return {
        'payment_verification_trend': payment_verification_trend,
        'sales_trend': [], # Placeholder for other potential charts
        'deal_status_distribution': {},
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

def get_profile_picture_url(user, request):
    """Safely get profile picture URL."""
    try:
        profile = UserProfile.objects.get(user=user)
        if profile.profile_picture:
            return request.build_absolute_uri(profile.profile_picture.url)
    except UserProfile.DoesNotExist:
        pass
    return None

def get_individual_standings(user, start_date, end_date, limit, request):
    """
    Calculate individual standings based on verified deals within a date range.
    Returns standings data, total participants, and current user's rank.
    """
    organization = user.organization
    if not organization:
        return [], 0, None

    # Optimize with annotations to eliminate N+1 queries
    all_salespersons = User.objects.filter(
        organization=organization,
        role__name__icontains='salesperson'
    ).select_related('role').annotate(
        total_sales=Sum(
            'created_deals__deal_value',
            filter=Q(created_deals__deal_date__range=(start_date, end_date), created_deals__verification_status='verified')
        ),
        deals_count=Count(
            'created_deals',
            filter=Q(created_deals__deal_date__range=(start_date, end_date), created_deals__verification_status='verified')
        ),
        max_deal_value=Max(
            'created_deals__deal_value',
            filter=Q(created_deals__deal_date__range=(start_date, end_date), created_deals__verification_status='verified')
        )
    ).order_by('-total_sales')

    total_participants = all_salespersons.count()
    current_user_rank = None

    standings = []
    for rank, person in enumerate(all_salespersons, 1):
        if person.id == user.id:
            current_user_rank = rank
        
        if rank > limit:
            continue

        standings.append({
            'rank': rank,
            'user_id': person.id,
            'username': f"{person.first_name} {person.last_name}".strip(),
            'sales_amount': person.total_sales or Decimal('0.00'),
            'profile_picture': get_profile_picture_url(person, request),
            'deals_count': person.deals_count or 0,
            'streak': person.streak,
            'performance_score': 0, # Placeholder
            'is_current_user': person.id == user.id
        })
    return standings, total_participants, current_user_rank

def get_team_standings(user, start_date, end_date, limit, request):
    """
    Calculate team standings based on verified deals within a date range.
    Returns standings data, total participants, and current user's team rank.
    """
    organization = user.organization
    if not organization:
        return [], 0, None
    
    # Optimize with annotations to eliminate N+1 queries
    all_teams = Team.objects.filter(organization=organization).select_related(
        'team_lead'
    ).prefetch_related('members').annotate(
        total_sales=Sum(
            'members__created_deals__deal_value',
            filter=Q(members__created_deals__deal_date__range=(start_date, end_date), members__created_deals__verification_status='verified')
        ),
        member_count=Count('members'),
        team_deals_count=Count(
            'members__created_deals',
            filter=Q(members__created_deals__deal_date__range=(start_date, end_date), members__created_deals__verification_status='verified')
        ),
        avg_streak=Avg('members__streak')
    ).order_by('-total_sales')
    
    total_participants = all_teams.count()
    current_user_team_rank = None
    user_team = Team.objects.filter(members=user).first()

    standings = []
    for rank, team in enumerate(all_teams, 1):
        if user_team and team.id == user_team.id:
            current_user_team_rank = rank

        if rank > limit:
            continue

        standings.append({
            'rank': rank,
            'team_id': team.id,
            'team_name': team.name,
            'sales_amount': team.total_sales or Decimal('0.00'),
            'member_count': team.member_count or 0,
            'team_deals': team.team_deals_count or 0,
            'avg_streak': team.avg_streak or 0,
            'team_lead_profile_picture': get_profile_picture_url(team.team_lead, request) if team.team_lead else None,
            'is_user_team': user_team and team.id == user_team.id
        })
    return standings, total_participants, current_user_team_rank

def get_top_clients_data(user, start_date, include_details=False):
    """
    Get data for top clients based on deal value.
    """
    top_clients_qs = Deal.objects.filter(
        created_by=user,
        deal_date__gte=start_date,
        verification_status__in=['verified', 'partial']
    ).values('client_id', 'client__client_name').annotate(
        total_deals=Count('id'),
        total_value=Sum('deal_value')
    ).order_by('-total_value')[:5]

    top_clients = []
    for client_data in top_clients_qs:
        client_deals = []
        if include_details:
            deals_qs = Deal.objects.filter(
                created_by=user,
                client_id=client_data['client_id'],
                deal_date__gte=start_date
            ).select_related('client').order_by('-deal_date')

            for deal in deals_qs:
                client_deals.append({
                    'id': deal.id,
                    'deal_value': deal.deal_value,
                    'deal_date': deal.deal_date,
                    'status': deal.verification_status,
                })

        top_clients.append({
            'client_id': client_data['client_id'],
            'client_name': client_data['client__client_name'],
            'total_deals': client_data['total_deals'],
            'total_value': client_data['total_value'],
            'deals': client_deals,
        })
    return top_clients

def get_all_time_top_clients_data(user):
    """
    Get top 5 regular clients based on total deal value of all time.
    """
    top_clients = Deal.objects.filter(
        created_by__organization=user.organization,
        verification_status='verified'
    ).values(
        'client_id', 'client__client_name'
    ).annotate(
        total_deals=Count('id'),
        total_value=Sum('deal_value')
    ).order_by('-total_value')[:5]
    
    return list(top_clients)

def get_commission_trends(user, period, start_date):
    """Get commission trend data for charts."""
    if period == 'yearly':
        trunc_period = TruncMonth
    elif period == 'quarterly':
        trunc_period = TruncWeek
    else:  # monthly
        trunc_period = TruncDay

    trends = Commission.objects.filter(
        user=user,
        created_at__gte=start_date
    ).annotate(
        period_start=trunc_period('created_at')
    ).values('period_start').annotate(
        total_commission=Sum('converted_amount')
    ).order_by('period_start')

    return [
        {
            'date': item['period_start'].strftime('%Y-%m-%d'),
            'total_commission': item['total_commission']
        }
        for item in trends
    ]

# ==================== Front-end compatibility alias endpoints ====================

# Note: Use minimal logic; these endpoints proxy existing helper functions or aggregate data

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def chart_view(request):
    """
    Returns chart data for the dashboard.
    Equivalent to the internal chart_data structure used in dashboard_view.
    """
    period = request.GET.get('period', 'monthly')
    now = timezone.now()
    if period == 'daily':
        start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
    elif period == 'weekly':
        start_date = now - timedelta(days=now.weekday())
        start_date = start_date.replace(hour=0, minute=0, second=0, microsecond=0)
    elif period == 'yearly':
        start_date = now.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
    else:
        start_date = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

    data = get_chart_data(request.user, period, start_date, now)
    return Response(data, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def goals_view(request):
    """
    Returns the user's sales goals progress (target, achieved, percentage).
    """
    user = request.user
    target = user.sales_target or Decimal('25000')
    achieved = Deal.objects.filter(
        created_by=user,
        verification_status='verified'
    ).aggregate(total=Sum('deal_value'))['total'] or Decimal('0')

    percentage = float((achieved / target) * 100) if target else 0
    return Response({
        'target': str(target),
        'achieved': str(achieved),
        'percentage': round(percentage, 2)
    }, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def payment_verification_view(request):
    """
    Returns counts and totals of deals by verification status for the current user.
    """
    summary_qs = Deal.objects.filter(created_by=request.user).values('verification_status').annotate(
        count=Count('id'),
        total_value=Sum('deal_value')
    )

    output = {
        'pending': {'count': 0, 'total': 0.0},
        'verified': {'count': 0, 'total': 0.0},
        'rejected': {'count': 0, 'total': 0.0},
    }

    for row in summary_qs:
        status_key = row['verification_status']
        if status_key in output:
            output[status_key]['count'] = row['count']
            output[status_key]['total'] = float(row['total_value'] or 0)

    return Response(output, status=status.HTTP_200_OK)
