from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.db.models import Sum, Q
from django.utils import timezone
from .serializers import DashboardSerializer, DailyStandingsSerializer, CommissionOverviewSerializer, SalespersonClientSerializer
from deals.models import Deal
from team.models import Team
from collections import defaultdict
from datetime import timedelta
from decimal import Decimal

# Create your views here.

class DashboardView(APIView):
    def get(self, request):
        user = request.user
        organization = user.organization
        period = request.query_params.get('period', 'monthly').lower()

        # 1. Current Sales
        current_sales = Deal.objects.filter(
            created_by=user,
            deal_status='verified'
        ).aggregate(total=Sum('deal_value'))['total'] or 0

        # 2. Payment Verification Status
        payment_status = Deal.objects.filter(
            created_by=user
        ).aggregate(
            cleared_amount=Sum('deal_value', filter=Q(deal_status='verified')),
            not_verified_amount=Sum('deal_value', filter=Q(deal_status='pending')),
            rejected_amount=Sum('deal_value', filter=Q(deal_status='rejected'))
        )

        # 3. Outstanding Deals
        outstanding_deals = Deal.objects.filter(
            created_by=user,
            pay_status='partial_payment'
        ).order_by('-deal_value')[:5]

        # 4. Payment Verification Graph
        today = timezone.now().date()
        graph_data = []
        if period == 'monthly':
            for i in range(12):
                month = today.month - i
                year = today.year
                if month <= 0:
                    month += 12
                    year -= 1
                amount = Deal.objects.filter(
                    created_by=user,
                    deal_status='verified',
                    deal_date__year=year,
                    deal_date__month=month
                ).aggregate(total=Sum('deal_value'))['total'] or 0
                graph_data.append({'date': f'{year}-{month:02d}', 'amount': amount})
        elif period == 'weekly':
            for i in range(7):
                day = today - timedelta(days=i)
                amount = Deal.objects.filter(
                    created_by=user,
                    deal_status='verified',
                    deal_date=day
                ).aggregate(total=Sum('deal_value'))['total'] or 0
                graph_data.append({'date': day.strftime('%Y-%m-%d'), 'amount': amount})

        dashboard_data = {
            'user': user,
            'current_sales': current_sales,
            'payment_verification_status': {
                'cleared_amount': payment_status['cleared_amount'] or 0,
                'not_verified_amount': payment_status['not_verified_amount'] or 0,
                'rejected_amount': payment_status['rejected_amount'] or 0,
            },
            'outstanding_deals': outstanding_deals,
            'payment_verification_graph': graph_data
        }

        serializer = DashboardSerializer(dashboard_data)
        return Response(serializer.data)

class DailyStandingsView(APIView):
    def get(self, request):
        user = request.user
        organization = user.organization
        standings_type = request.query_params.get('type', 'individual').lower()
        today = timezone.now().date()

        if standings_type == 'individual':
            standings_query = Deal.objects.filter(
                organization=organization,
                deal_date=today
            ).values('created_by__username').annotate(
                amount=Sum('deal_value')
            ).order_by('-amount')
            
            standings = [{'name': s['created_by__username'], 'amount': s['amount']} for s in standings_query]

        elif standings_type == 'team':
            team_sales = defaultdict(float)
            deals_today = Deal.objects.filter(
                organization=organization,
                deal_date=today
            ).select_related('created_by')

            for deal in deals_today:
                user_teams = Team.objects.filter(members=deal.created_by)
                for team in user_teams:
                    team_sales[team.name] += float(deal.deal_value)
            
            standings = [{'name': name, 'amount': amount} for name, amount in sorted(team_sales.items(), key=lambda item: item[1], reverse=True)]
        
        else:
            return Response({"error": "Invalid type parameter"}, status=status.HTTP_400_BAD_REQUEST)

        serializer = DailyStandingsSerializer(standings, many=True)
        return Response(serializer.data)

class CommissionOverviewView(APIView):
    def get(self, request):
        user = request.user
        organization = user.organization
        today = timezone.now().date()

        # 1. Company Goal
        current_month_sales = Deal.objects.filter(
            organization=organization,
            deal_date__year=today.year,
            deal_date__month=today.month
        ).aggregate(total=Sum('deal_value'))['total'] or 0

        last_month = today - timedelta(days=30)
        last_month_sales = Deal.objects.filter(
            organization=organization,
            deal_date__year=last_month.year,
            deal_date__month=last_month.month
        ).aggregate(total=Sum('deal_value'))['total'] or 0
        
        monthly_growth = Decimal('0')
        if last_month_sales > 0:
            monthly_growth = ((Decimal(current_month_sales) - Decimal(last_month_sales)) / Decimal(last_month_sales)) * Decimal('100')

        company_goal_data = {
            'sales_goal': organization.sales_goal,
            'current_sales': current_month_sales,
            'percentage_achieved': (Decimal(current_month_sales) / Decimal(organization.sales_goal)) * 100 if organization.sales_goal > 0 else 0,
            'monthly_growth': monthly_growth
        }

        # 2. Top Clients (for the logged-in user)
        period = request.query_params.get('period', 'monthly').lower()
        top_clients_query = Deal.objects.filter(created_by=user)
        if period == 'monthly':
            top_clients_query = top_clients_query.filter(deal_date__year=today.year, deal_date__month=today.month)
        elif period == 'weekly':
            start_of_week = today - timedelta(days=today.weekday())
            top_clients_query = top_clients_query.filter(deal_date__gte=start_of_week)
        elif period == 'daily':
            top_clients_query = top_clients_query.filter(deal_date=today)
            
        top_clients = top_clients_query.values('client_name').annotate(total_sales=Sum('deal_value')).order_by('-total_sales')[:5]

        # 3. Regular Clients (top 5 all-time for the user)
        regular_clients = Deal.objects.filter(created_by=user).values('client_name').annotate(total_sales=Sum('deal_value')).order_by('-total_sales')[:5]

        serializer = CommissionOverviewSerializer({
            'company_goal': company_goal_data,
            'top_clients': top_clients,
            'regular_clients': regular_clients
        })
        return Response(serializer.data)

class SalespersonClientListView(APIView):
    def get(self, request):
        user = request.user
        clients = Deal.objects.filter(created_by=user).values('client_name').distinct()
        
        client_data = []
        for client in clients:
            client_name = client['client_name']
            deals = Deal.objects.filter(created_by=user, client_name=client_name)
            total_sales = deals.aggregate(total=Sum('deal_value'))['total'] or 0
            
            status = 'Clear'
            if deals.filter(pay_status='partial_payment').exists():
                status = 'Pending'
            if deals.filter(due_date__lt=timezone.now().date(), pay_status='partial_payment').exists():
                status = 'Bad Debt'

            # Assuming remarks come from the Client model, which we don't have a direct link to.
            # This part needs to be adjusted if a Client model with remarks exists.
            # For now, we'll use a placeholder.
            remarks = "No remarks available."
            
            client_data.append({
                'client_name': client_name,
                'total_sales': total_sales,
                'status': status,
                'remarks': remarks
            })

        serializer = SalespersonClientSerializer(client_data, many=True)
        return Response(serializer.data)
