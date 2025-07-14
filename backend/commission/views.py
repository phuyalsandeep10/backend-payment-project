from decimal import Decimal
from django.db.models import Sum
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
import csv
import json

from authentication.models import User
from deals.models import Deal
from permissions.permissions import IsOrgAdminOrSuperAdmin

from .models import Commission
from .permissions import HasCommissionPermission
from .serializers import CommissionSerializer


class CommissionViewSet(viewsets.ModelViewSet):
    """
    A viewset for managing commissions.
    The backend automatically calculates total_sales and commission amounts
    when a commission record is created or updated.
    """
    serializer_class = CommissionSerializer
    permission_classes = [HasCommissionPermission]

    def get_queryset(self):
        """
        Returns commissions for the user's organization.
        Superusers can see all commissions.
        Users with 'view_all_commissions' can see all commissions in their organization.
        Regular users can only see their own commissions.
        """
        if getattr(self, 'swagger_fake_view', False) or not self.request.user.is_authenticated:
            return Commission.objects.none()
            
        user = self.request.user

        queryset = Commission.objects.select_related(
            'user', 'organization', 'created_by', 'updated_by'
        )

        if user.is_superuser:
            org_id = self.request.query_params.get('organization')
            if org_id:
                return queryset.filter(organization_id=org_id)
            return queryset.all()
        
        if not hasattr(user, 'organization') or not user.organization:
            return Commission.objects.none()

        organization_queryset = queryset.filter(organization=user.organization)

        is_org_admin = user.role and user.role.name == 'Org Admin'
        can_view_all = user.role and user.role.permissions.filter(codename='view_all_commissions').exists()
        
        if is_org_admin or can_view_all:
            return organization_queryset
        
        return organization_queryset.filter(user=user)

    def get_serializer_context(self):
        """Pass the request to the serializer context."""
        return {'request': self.request}

    @action(detail=False, methods=['put'], url_path='bulk-update')
    def bulk_update(self, request):
        """
        Bulk update commissions. Expects a list of commission objects.
        """
        commission_data = request.data
        if not isinstance(commission_data, list):
            return Response({'error': 'Expected a list of commission data'}, status=status.HTTP_400_BAD_REQUEST)
        
        updated_commissions = []
        for data in commission_data:
            commission_id = data.get('id')
            if not commission_id:
                continue
            
            try:
                commission = Commission.objects.get(id=commission_id)
                # Basic permission check
                if not request.user.is_superuser and commission.organization != request.user.organization:
                    continue
                
                serializer = self.get_serializer(commission, data=data, partial=True)
                if serializer.is_valid(raise_exception=True):
                    serializer.save()
                    updated_commissions.append(serializer.data)
            except Commission.DoesNotExist:
                continue
        
        return Response(updated_commissions)

    @action(detail=True, methods=['post'])
    def calculate(self, request, pk=None):
        """
        Recalculates a specific commission record by re-saving it.
        """
        commission = self.get_object()
        commission.save() # The model's save() method triggers recalculation
        return Response(self.get_serializer(commission).data)

    @action(detail=False, methods=['get'])
    def export(self, request):
        """
        Export commissions in CSV or JSON format.
        Use ?format=csv or ?format=json
        """
        queryset = self.get_queryset()
        export_format = request.query_params.get('format', 'json').lower()

        if export_format == 'csv':
            response = HttpResponse(content_type='text/csv')
            response['Content-Disposition'] = 'attachment; filename="commissions.csv"'
            
            writer = csv.writer(response)
            writer.writerow([
                'User', 'Total Sales', 'Currency', 'Commission Rate (%)', 
                'Exchange Rate', 'Bonus', 'Penalty', 'Calculated Commission', 
                'Total Commission (with Bonus)', 'Total Receivable (after Penalty)'
            ])
            
            for commission in queryset:
                writer.writerow([
                    commission.user.email,
                    commission.total_sales,
                    commission.currency,
                    commission.commission_rate,
                    commission.exchange_rate,
                    commission.bonus,
                    commission.penalty,
                    commission.commission_amount,
                    commission.total_commission,
                    commission.total_receivable,
                ])
            
            return response
        
        # Default to JSON
        data = self.get_serializer(queryset, many=True).data
        return Response(data)


class UserCommissionView(APIView):
    """Retrieve all commission records for a specific user."""
    permission_classes = [IsOrgAdminOrSuperAdmin]

    def get(self, request, user_id):
        user = get_object_or_404(User, pk=user_id)

        if not request.user.is_superuser and user.organization != request.user.organization:
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)

        commissions = Commission.objects.filter(user_id=user_id)
        serializer = CommissionSerializer(commissions, many=True, context={'request': request})
        return Response(serializer.data)


class OrgAdminCommissionView(APIView):
    """Get commission data for all salespeople in the organization for org-admin."""
    permission_classes = [IsOrgAdminOrSuperAdmin]

    def get(self, request):
        """Get aggregated commission data for all salespeople in the organization."""
        try:
            user = request.user
            organization = user.organization
            
            if not organization:
                return Response({'error': 'User must belong to an organization'}, status=status.HTTP_400_BAD_REQUEST)

            # Get all salespeople in the organization
            salespeople = User.objects.filter(
                organization=organization,
                role__name__in=['Salesperson', 'Senior Salesperson']
            ).select_related('role')

            commission_data = []
            
            for salesperson in salespeople:
                # Calculate total sales for this salesperson
                total_sales = Deal.objects.filter(
                    created_by=salesperson,
                    verification_status__in=['verified', 'partial']
                ).aggregate(Sum('deal_value'))['deal_value__sum'] or Decimal('0.00')
                
                # Get existing commission record or create default values
                commission_record = Commission.objects.filter(
                    user=salesperson,
                    organization=organization
                ).first()
                
                if commission_record:
                    # Use existing commission settings
                    commission_data.append({
                        'id': commission_record.id,
                        'fullName': f"{salesperson.first_name} {salesperson.last_name}".strip() or salesperson.username,
                        'totalSales': float(total_sales),
                        'currency': commission_record.currency,
                        'rate': float(commission_record.exchange_rate),
                        'percentage': float(commission_record.commission_rate),
                        'bonus': float(commission_record.bonus),
                        'penalty': float(commission_record.penalty),
                        'convertedAmt': float(commission_record.commission_amount),
                        'total': float(commission_record.total_commission),
                        'totalReceivable': float(commission_record.total_receivable),
                    })
                else:
                    # Create default commission data
                    commission_data.append({
                        'id': None,
                        'fullName': f"{salesperson.first_name} {salesperson.last_name}".strip() or salesperson.username,
                        'totalSales': float(total_sales),
                        'currency': 'USD',
                        'rate': 1.0,
                        'percentage': 5.0,  # Default 5% commission
                        'bonus': 0.0,
                        'penalty': 0.0,
                        'convertedAmt': float(total_sales * Decimal('0.05')),  # 5% of total sales
                        'total': float(total_sales * Decimal('0.05')),
                        'totalReceivable': float(total_sales * Decimal('0.05')),
                    })
            
            return Response(commission_data, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
