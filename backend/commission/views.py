from django.shortcuts import render
from rest_framework import viewsets, status
from rest_framework.response import Response
from django.db.models import Sum
from .models import Commission
from deals.models import Deal
from .serializers import CommissionSerializer
from .permissions import HasCommissionPermission
from decimal import Decimal

# Create your views here.

class CommissionViewSet(viewsets.ModelViewSet):
    """
    A viewset for managing commissions.
    - `total_sales` is calculated automatically based on verified, full_payment deals
      for the specified user and date range.
    - Other commission parameters are provided in the request.
    """
    serializer_class = CommissionSerializer
    permission_classes = [HasCommissionPermission]

    def get_queryset(self):
        """
        Returns commissions for the user's organization.
        Superusers can see all commissions across all organizations.
        """
        if getattr(self, 'swagger_fake_view', False) or not self.request.user.is_authenticated:
            return Commission.objects.none()
            
        user = self.request.user

        queryset = Commission.objects.select_related(
            'user', 'organization', 'created_by', 'updated_by'
        )

        if user.is_superuser:
            # Allow filtering by organization for superusers
            org_id = self.request.query_params.get('organization')
            if org_id:
                return queryset.filter(organization_id=org_id)
            return queryset.all()
        
        if not hasattr(user, 'organization') or not user.organization:
            return Commission.objects.none()

        organization_queryset = queryset.filter(organization=user.organization)

        # OrgAdmins and those with 'view_all_commissions' can see all org commissions
        is_org_admin = hasattr(user, 'is_org_admin') and user.is_org_admin
        can_view_all = (
            hasattr(user, 'role') and 
            user.role and 
            user.role.permissions.filter(codename='view_all_commissions').exists()
        )
        
        if is_org_admin or can_view_all:
            return organization_queryset
        
        # Regular users can only see their own commissions
        return organization_queryset.filter(user=user)

    def _calculate_total_sales(self, user, start_date, end_date):
        """Calculates total sales from verified deals for a user in a date range."""
        total_sales = Deal.objects.filter(
            created_by=user,
            deal_date__range=[start_date, end_date],
            verification_status='verified',
            payment_status='full_payment'
        ).aggregate(total=Sum('deal_value'))['total'] or Decimal('0.00')
        return total_sales

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = serializer.validated_data['user']
        start_date = serializer.validated_data['start_date']
        end_date = serializer.validated_data['end_date']

        total_sales = self._calculate_total_sales(user, start_date, end_date)
        
        # Calculate the fields based on the provided logic
        commission_rate = serializer.validated_data.get('commission_rate', Decimal('0.0'))
        exchange_rate = serializer.validated_data.get('exchange_rate', Decimal('1.0'))
        bonus = serializer.validated_data.get('bonus', Decimal('0.0'))
        penalty = serializer.validated_data.get('penalty', Decimal('0.0'))

        # 1. Converted Amount = commission_rate % of total_sales
        converted_amount = total_sales * (commission_rate / Decimal('100.0'))
        
        # 2. Total Commission = converted_amount * exchange_rate + bonus
        total_commission = (converted_amount * exchange_rate) + bonus
        
        # 3. Total Receivable = total_commission - penalty
        total_receivable = total_commission - penalty

        # The 'commission_amount' field can now be deprecated or used for the final converted value
        commission_amount = converted_amount * exchange_rate
        
        serializer.save(
            organization=self.request.user.organization,
            created_by=self.request.user,
            total_sales=total_sales,
            converted_amount=converted_amount,
            commission_amount=commission_amount,
            total_commission=total_commission,
            total_receivable=total_receivable
        )
        
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data.get('user', instance.user)
        start_date = serializer.validated_data.get('start_date', instance.start_date)
        end_date = serializer.validated_data.get('end_date', instance.end_date)
        
        total_sales = self._calculate_total_sales(user, start_date, end_date)
        
        # Pass total_sales to the serializer's save method
        self.perform_update(serializer, total_sales=total_sales)

        if getattr(instance, '_prefetched_objects_cache', None):
            instance._prefetched_objects_cache = {}

        return Response(serializer.data)

    def perform_create(self, serializer, total_sales):
        """
        Set the creator of the commission record and the calculated total_sales.
        """
        serializer.save(created_by=self.request.user, total_sales=total_sales)

    def perform_update(self, serializer, total_sales):
        """
        Set the user who last updated the commission record and the calculated total_sales.
        """
        serializer.save(updated_by=self.request.user, total_sales=total_sales)

    def get_serializer_context(self):
        """
        Pass the request to the serializer context.
        """
        return {'request': self.request}
