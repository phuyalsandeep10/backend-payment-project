from django.shortcuts import render, get_object_or_404
from django.http import HttpResponse
from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.decorators import action
from .models import Commission
from .serializers import CommissionSerializer
from permissions.permissions import IsOrgAdminOrSuperAdmin
import csv
import json
from rest_framework.views import APIView
from authentication.models import User  # Assuming custom user model lives here

# Create your views here.

class CommissionViewSet(viewsets.ModelViewSet):
    """
    A viewset for managing commissions.
    Access is restricted to Org Admins and Super Admins.
    """
    serializer_class = CommissionSerializer
    permission_classes = [IsOrgAdminOrSuperAdmin]

    def get_queryset(self):
        """
        Returns commissions for the user's organization.
        Superusers can see all commissions across all organizations.
        """
        user = self.request.user
        if user.is_superuser:
            return Commission.objects.all()
        
        if user.organization:
            return Commission.objects.filter(organization=user.organization)
            
        return Commission.objects.none() # No org, no commissions

    def get_serializer_context(self):
        """
        Pass the request to the serializer context.
        """
        return {'request': self.request}

    def perform_create(self, serializer):
        """
        Associate commission with the user's organization.
        """
        if not self.request.user.is_superuser:
            serializer.save(organization=self.request.user.organization)
        else:
            serializer.save()

    def bulk_update(self, request):
        """
        Bulk update commissions.
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
                # Check permissions
                if not request.user.is_superuser and commission.organization != request.user.organization:
                    continue
                
                serializer = CommissionSerializer(commission, data=data, partial=True)
                if serializer.is_valid():
                    serializer.save()
                    updated_commissions.append(serializer.data)
            except Commission.DoesNotExist:
                continue
        
        return Response(updated_commissions)

    @action(detail=True, methods=['post'])
    def calculate(self, request, pk=None):
        """
        Recalculate commission for a specific commission record.
        """
        commission = self.get_object()
        commission.calculate_commission()
        commission.save()
        return Response(CommissionSerializer(commission).data)

    def export(self, request, format=None):
        """
        Export commissions in CSV or PDF format.
        """
        queryset = self.get_queryset()
        
        # Apply filters if provided
        currency = request.query_params.get('currency')
        if currency:
            queryset = queryset.filter(currency=currency)
        
        if format == 'csv':
            response = HttpResponse(content_type='text/csv')
            response['Content-Disposition'] = 'attachment; filename="commissions.csv"'
            
            writer = csv.writer(response)
            writer.writerow(['Full Name', 'Total Sales', 'Currency', 'Rate', 'Percentage', 'Bonus', 'Penalty', 'Total', 'Total Receivable'])
            
            for commission in queryset:
                writer.writerow([
                    commission.full_name,
                    commission.total_sales,
                    commission.currency,
                    commission.rate,
                    commission.percentage,
                    commission.bonus,
                    commission.penalty,
                    commission.total,
                    commission.total_receivable,
                ])
            
            return response
        
        elif format == 'pdf':
            # For PDF export, return JSON for now (implement PDF generation as needed)
            data = CommissionSerializer(queryset, many=True).data
            response = HttpResponse(json.dumps(data), content_type='application/json')
            response['Content-Disposition'] = 'attachment; filename="commissions.json"'
            return response
        
        return Response({'error': 'Unsupported format'}, status=status.HTTP_400_BAD_REQUEST)

class UserCommissionView(APIView):
    """Retrieve all commission records for a specific user."""
    permission_classes = [IsOrgAdminOrSuperAdmin]

    def get(self, request, user_id):
        # Validate user exists and belongs to same organization (unless superuser)
        user = get_object_or_404(User, pk=user_id)

        # Permission: superusers bypass org restriction
        if not request.user.is_superuser and user.organization != request.user.organization:
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)

        commissions = Commission.objects.filter(user_id=user_id)
        serializer = CommissionSerializer(commissions, many=True, context={'request': request})
        return Response(serializer.data)
