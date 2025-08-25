"""
Optimized Deal Views with Enhanced Query Performance
"""

from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
from django.db.models import Q
from datetime import datetime, timedelta
from .models import Deal, Payment
from .query_optimizer import DealQueryOptimizer, DealReportingOptimizer
from .serializers import DealSerializer
from permissions.permissions import IsOrgAdminOrSuperAdmin
from core_config.query_performance_middleware import monitor_org_query_performance
import logging

# Performance logger
performance_logger = logging.getLogger('performance')

class OptimizedDealViewSet(viewsets.ModelViewSet):
    """
    Enhanced Deal ViewSet with optimized queries and efficient pagination
    """
    serializer_class = DealSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        """Get optimized queryset for deals"""
        user = self.request.user
        organization = user.organization if hasattr(user, 'organization') else None
        
        return DealQueryOptimizer.get_optimized_deal_queryset(
            organization=organization,
            user=user
        )
    
    @monitor_org_query_performance
    def list(self, request, *args, **kwargs):
        """
        Enhanced list view with advanced filtering and pagination
        """
        user = request.user
        organization = user.organization if hasattr(user, 'organization') else None
        
        # Parse filters from query parameters
        filters = self._parse_filters(request.query_params)
        
        # Get filtered queryset
        queryset = DealQueryOptimizer.get_deals_with_filters(
            organization=organization,
            filters=filters,
            user=user
        )
        
        # Get pagination parameters
        page = int(request.query_params.get('page', 1))
        page_size = min(int(request.query_params.get('page_size', 25)), 100)  # Max 100 per page
        order_by = request.query_params.get('order_by', '-created_at')
        
        # Get paginated results
        paginated_data = DealQueryOptimizer.get_paginated_deals(
            queryset=queryset,
            page=page,
            page_size=page_size,
            order_by=order_by
        )
        
        # Serialize the deals
        serializer = self.get_serializer(paginated_data['deals'], many=True)
        
        return Response({
            'results': serializer.data,
            'pagination': paginated_data['pagination'],
            'filters_applied': filters,
            'query_performance': {
                'total_deals': paginated_data['pagination']['total_count'],
                'page_size': page_size,
                'current_page': page
            }
        })
    
    def _parse_filters(self, query_params):
        """Parse filters from query parameters"""
        filters = {}
        
        # Status filters
        if 'verification_status' in query_params:
            filters['verification_status'] = query_params.getlist('verification_status')
        
        if 'payment_status' in query_params:
            filters['payment_status'] = query_params.getlist('payment_status')
        
        # Date filters
        if 'date_from' in query_params:
            try:
                filters['date_from'] = datetime.strptime(query_params['date_from'], '%Y-%m-%d').date()
            except ValueError:
                pass
        
        if 'date_to' in query_params:
            try:
                filters['date_to'] = datetime.strptime(query_params['date_to'], '%Y-%m-%d').date()
            except ValueError:
                pass
        
        if 'created_from' in query_params:
            try:
                filters['created_from'] = datetime.strptime(query_params['created_from'], '%Y-%m-%d')
            except ValueError:
                pass
        
        if 'created_to' in query_params:
            try:
                filters['created_to'] = datetime.strptime(query_params['created_to'], '%Y-%m-%d')
            except ValueError:
                pass
        
        # Value filters
        if 'min_value' in query_params:
            try:
                filters['min_value'] = float(query_params['min_value'])
            except ValueError:
                pass
        
        if 'max_value' in query_params:
            try:
                filters['max_value'] = float(query_params['max_value'])
            except ValueError:
                pass
        
        # Other filters
        if 'source_type' in query_params:
            filters['source_type'] = query_params.getlist('source_type')
        
        if 'client_id' in query_params:
            try:
                filters['client_id'] = int(query_params['client_id'])
            except ValueError:
                pass
        
        if 'created_by' in query_params:
            try:
                filters['created_by'] = int(query_params['created_by'])
            except ValueError:
                pass
        
        if 'project_id' in query_params:
            try:
                filters['project_id'] = int(query_params['project_id'])
            except ValueError:
                pass
        
        if 'payment_method' in query_params:
            filters['payment_method'] = query_params.getlist('payment_method')
        
        if 'search' in query_params:
            filters['search'] = query_params['search'].strip()
        
        return filters
    
    @action(detail=False, methods=['get'], url_path='analytics')
    @monitor_org_query_performance
    def get_analytics(self, request):
        """
        Get comprehensive deal analytics
        """
        user = request.user
        organization = user.organization if hasattr(user, 'organization') else None
        
        # Parse date range
        date_from = None
        date_to = None
        
        if 'date_from' in request.query_params:
            try:
                date_from = datetime.strptime(request.query_params['date_from'], '%Y-%m-%d')
            except ValueError:
                pass
        
        if 'date_to' in request.query_params:
            try:
                date_to = datetime.strptime(request.query_params['date_to'], '%Y-%m-%d')
            except ValueError:
                pass
        
        # Get analytics
        analytics = DealQueryOptimizer.get_deal_analytics(
            organization=organization,
            date_from=date_from,
            date_to=date_to,
            user=user
        )
        
        return Response(analytics)
    
    @action(detail=False, methods=['get'], url_path='performance')
    @monitor_org_query_performance
    def get_performance_metrics(self, request):
        """
        Get deal performance metrics for dashboard
        """
        user = request.user
        organization = user.organization if hasattr(user, 'organization') else None
        
        metrics = DealQueryOptimizer.get_deal_performance_metrics(
            organization=organization,
            user=user
        )
        
        return Response(metrics)
    
    @action(detail=False, methods=['get'], url_path='search-suggestions')
    def get_search_suggestions(self, request):
        """
        Get search suggestions for deals
        """
        query = request.query_params.get('q', '').strip()
        limit = min(int(request.query_params.get('limit', 10)), 20)
        
        user = request.user
        organization = user.organization if hasattr(user, 'organization') else None
        
        suggestions = DealQueryOptimizer.get_deal_search_suggestions(
            query=query,
            organization=organization,
            limit=limit
        )
        
        return Response({
            'suggestions': suggestions,
            'query': query
        })
    
    @action(detail=False, methods=['get'], url_path='financial-summary')
    @monitor_org_query_performance
    def get_financial_summary(self, request):
        """
        Get financial summary for deals
        """
        user = request.user
        organization = user.organization if hasattr(user, 'organization') else None
        
        # Parse date range
        date_from = None
        date_to = None
        
        if 'date_from' in request.query_params:
            try:
                date_from = datetime.strptime(request.query_params['date_from'], '%Y-%m-%d')
            except ValueError:
                pass
        
        if 'date_to' in request.query_params:
            try:
                date_to = datetime.strptime(request.query_params['date_to'], '%Y-%m-%d')
            except ValueError:
                pass
        
        # Get financial summary
        deal_summary = DealReportingOptimizer.get_financial_summary(
            organization=organization,
            date_from=date_from,
            date_to=date_to
        )
        
        payment_summary = DealReportingOptimizer.get_payment_summary(
            organization=organization,
            date_from=date_from,
            date_to=date_to
        )
        
        return Response({
            'deal_summary': deal_summary,
            'payment_summary': payment_summary,
            'date_range': {
                'from': date_from.isoformat() if date_from else None,
                'to': date_to.isoformat() if date_to else None
            },
            'generated_at': timezone.now().isoformat()
        })
    
    @action(detail=False, methods=['post'], url_path='bulk-update-status')
    @monitor_org_query_performance
    def bulk_update_status(self, request):
        """
        Bulk update verification status for multiple deals
        """
        deal_ids = request.data.get('deal_ids', [])
        new_status = request.data.get('verification_status')
        
        if not deal_ids or not new_status:
            return Response(
                {'error': 'deal_ids and verification_status are required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        user = request.user
        organization = user.organization if hasattr(user, 'organization') else None
        
        # Get deals to update
        queryset = self.get_queryset().filter(id__in=deal_ids)
        
        if not user.is_superuser and organization:
            queryset = queryset.filter(organization=organization)
        
        updated_count = 0
        failed_updates = []
        
        for deal in queryset:
            try:
                # Validate status transition
                deal.validate_verification_status_transition(new_status)
                deal.verification_status = new_status
                deal.updated_by = user
                deal.save(update_fields=['verification_status', 'updated_by', 'updated_at'])
                updated_count += 1
            except Exception as e:
                failed_updates.append({
                    'deal_id': str(deal.id),
                    'error': str(e)
                })
        
        # Invalidate caches
        DealQueryOptimizer.invalidate_deal_caches(organization.id if organization else None)
        
        return Response({
            'updated_count': updated_count,
            'failed_updates': failed_updates,
            'total_requested': len(deal_ids)
        })
    
    @action(detail=False, methods=['get'], url_path='export-data')
    @monitor_org_query_performance
    def export_deals_data(self, request):
        """
        Export deals data with filters (returns data for CSV/Excel export)
        """
        user = request.user
        organization = user.organization if hasattr(user, 'organization') else None
        
        # Parse filters
        filters = self._parse_filters(request.query_params)
        
        # Get filtered queryset (limit to reasonable size for export)
        queryset = DealQueryOptimizer.get_deals_with_filters(
            organization=organization,
            filters=filters,
            user=user
        )[:5000]  # Limit to 5000 records for export
        
        # Prepare export data
        export_data = []
        for deal in queryset:
            export_data.append({
                'deal_id': deal.deal_id,
                'deal_name': deal.deal_name,
                'client_name': deal.client.client_name if deal.client else '',
                'deal_value': float(deal.deal_value),
                'currency': deal.currency,
                'verification_status': deal.verification_status,
                'payment_status': deal.payment_status,
                'source_type': deal.source_type,
                'payment_method': deal.payment_method,
                'deal_date': deal.deal_date.isoformat(),
                'due_date': deal.due_date.isoformat() if deal.due_date else None,
                'created_at': deal.created_at.isoformat(),
                'created_by': deal.created_by.email if deal.created_by else '',
                'project_name': deal.project.name if deal.project else '',
                'client_status': deal.client_status,
                'payment_count': deal.payment_count,
                'total_paid': deal.get_total_paid_amount(),
                'remaining_balance': deal.get_remaining_balance(),
                'payment_progress': deal.get_payment_progress(),
            })
        
        return Response({
            'data': export_data,
            'total_records': len(export_data),
            'filters_applied': filters,
            'exported_at': timezone.now().isoformat()
        })


class DealReportingViewSet(viewsets.ViewSet):
    """
    Specialized viewset for deal reporting with optimized queries
    """
    permission_classes = [IsAuthenticated, IsOrgAdminOrSuperAdmin]
    
    @action(detail=False, methods=['get'], url_path='dashboard-summary')
    @monitor_org_query_performance
    def get_dashboard_summary(self, request):
        """
        Get comprehensive dashboard summary for deals
        """
        user = request.user
        organization = user.organization if hasattr(user, 'organization') else None
        
        # Get current month data
        current_month_start = timezone.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        
        # Get various time period summaries
        summaries = {
            'current_month': DealReportingOptimizer.get_financial_summary(
                organization=organization,
                date_from=current_month_start
            ),
            'last_30_days': DealReportingOptimizer.get_financial_summary(
                organization=organization,
                date_from=timezone.now() - timedelta(days=30)
            ),
            'last_90_days': DealReportingOptimizer.get_financial_summary(
                organization=organization,
                date_from=timezone.now() - timedelta(days=90)
            ),
            'year_to_date': DealReportingOptimizer.get_financial_summary(
                organization=organization,
                date_from=timezone.now().replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
            )
        }
        
        # Get payment summaries
        payment_summaries = {
            'current_month': DealReportingOptimizer.get_payment_summary(
                organization=organization,
                date_from=current_month_start
            ),
            'last_30_days': DealReportingOptimizer.get_payment_summary(
                organization=organization,
                date_from=timezone.now() - timedelta(days=30)
            )
        }
        
        return Response({
            'deal_summaries': summaries,
            'payment_summaries': payment_summaries,
            'generated_at': timezone.now().isoformat()
        })
    
    @action(detail=False, methods=['get'], url_path='trend-analysis')
    @monitor_org_query_performance
    def get_trend_analysis(self, request):
        """
        Get trend analysis for deals over time
        """
        user = request.user
        organization = user.organization if hasattr(user, 'organization') else None
        
        # Get analytics with trends
        analytics = DealQueryOptimizer.get_deal_analytics(
            organization=organization,
            date_from=timezone.now() - timedelta(days=365),  # Last year
            user=user
        )
        
        return Response({
            'trends': analytics['monthly_trends'],
            'source_analysis': analytics['source_analysis'],
            'top_performers': {
                'clients': analytics['top_clients'],
                'creators': analytics['top_creators']
            },
            'generated_at': timezone.now().isoformat()
        })