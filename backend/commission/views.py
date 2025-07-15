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
import pycountry

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

    @action(detail=False, methods=['put'], url_path='bulk-update', permission_classes=[IsOrgAdminOrSuperAdmin])
    def bulk_update(self, request):
        """
        Bulk update commissions. Expects a list of commission objects.
        Creates new commission records if they don't exist.
        """
        commission_data = request.data
        if not isinstance(commission_data, list):
            return Response({'error': 'Expected a list of commission data'}, status=status.HTTP_400_BAD_REQUEST)
        
        updated_commissions = []
        for data in commission_data:
            commission_id = data.get('id')
            user_id = data.get('user_id')
            
            try:
                if commission_id and commission_id != 'null' and commission_id != 'undefined':
                    # Update existing commission
                    commission = Commission.objects.get(id=commission_id)
                    # Basic permission check
                    if not request.user.is_superuser and commission.organization != request.user.organization:
                        continue
                    
                    serializer = self.get_serializer(commission, data=data, partial=True)
                else:
                    # Create new commission record
                    if not user_id:
                        continue
                    
                    # Get the user
                    from authentication.models import User
                    user = User.objects.get(id=user_id)
                    
                    # Check if commission already exists for this user
                    existing_commission = Commission.objects.filter(
                        user=user,
                        organization=request.user.organization
                    ).first()
                    
                    if existing_commission:
                        # Update existing record
                        serializer = self.get_serializer(existing_commission, data=data, partial=True)
                    else:
                        # Create new record
                        data['user_id'] = user_id
                        data['organization'] = request.user.organization.id
                        data['start_date'] = data.get('start_date', '2024-01-01')  # Default start date
                        data['end_date'] = data.get('end_date', '2024-12-31')      # Default end date
                        serializer = self.get_serializer(data=data)
                
                if serializer.is_valid(raise_exception=True):
                    serializer.save()
                    updated_commissions.append(serializer.data)
                    
            except (Commission.DoesNotExist, User.DoesNotExist):
                continue
            except Exception as e:
                continue
        
        return Response({
            'message': f'Successfully updated {len(updated_commissions)} commission records',
            'updated_commissions': updated_commissions
        })

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

    @action(detail=False, methods=['post'], url_path='export-selected')
    def export_selected(self, request):
        """
        Export selected salespeople commissions in CSV or JSON format.
        Expects a list of user IDs in the request body.
        """
        try:
            user_ids = request.data.get('user_ids', [])
            if not user_ids:
                return Response({'error': 'No user IDs provided'}, status=status.HTTP_400_BAD_REQUEST)
            
            # Get commissions for selected users
            queryset = Commission.objects.filter(
                user_id__in=user_ids,
                organization=request.user.organization
            ).select_related('user')
            
            export_format = request.query_params.get('format', 'csv').lower()
            
            if export_format == 'csv':
                response = HttpResponse(content_type='text/csv')
                response['Content-Disposition'] = 'attachment; filename="selected_commissions.csv"'
                
                writer = csv.writer(response)
                writer.writerow([
                    'Salesperson Name', 'Total Sales (Verified)', 'Currency', 'Commission Rate (%)', 
                    'Exchange Rate', 'Bonus', 'Penalty', 'Converted Amount', 
                    'Total Commission', 'Total Receivable'
                ])
                
                for commission in queryset:
                    writer.writerow([
                        f"{commission.user.first_name} {commission.user.last_name}".strip() or commission.user.username,
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
            
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


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
                # Calculate total sales for this salesperson (ONLY VERIFIED DEALS)
                total_sales = Deal.objects.filter(
                    created_by=salesperson,
                    verification_status='verified'  # Only verified deals count
                ).aggregate(Sum('deal_value'))['deal_value__sum'] or Decimal('0.00')
                
                # Get existing commission record or create default values
                commission_record = Commission.objects.filter(
                    user=salesperson,
                    organization=organization
                ).first()
                
                if commission_record:
                    # Use existing commission settings - update total_sales first
                    commission_record.total_sales = total_sales
                    commission_record.save()  # This will recalculate amounts
                    
                    commission_data.append({
                        'id': commission_record.id,
                        'user_id': salesperson.id,
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
                        'user_id': salesperson.id,
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


class CurrencyListView(APIView):
    """Get all supported currencies with their details."""
    permission_classes = []  # No permissions required - accessible to all users

    def get(self, request):
        """Return top 50 most used currencies with their details."""
        try:
            # Top 50 most used currencies with country mapping
            top_currencies = [
                'USD', 'EUR', 'GBP', 'JPY', 'CNY', 'AUD', 'CAD', 'CHF', 'NPR', 'INR',
                'BRL', 'MXN', 'KRW', 'SGD', 'HKD', 'SEK', 'NOK', 'DKK', 'RUB', 'TRY',
                'ZAR', 'PLN', 'CZK', 'HUF', 'ILS', 'CLP', 'PHP', 'THB', 'MYR', 'IDR',
                'VND', 'EGP', 'NGN', 'KES', 'GHS', 'UGX', 'TZS', 'ARS', 'COP', 'PEN',
                'UYU', 'ISK', 'NZD', 'AED', 'SAR', 'QAR', 'KWD', 'BHD', 'OMR', 'JOD'
            ]

            # Enhanced currency to country mapping
            currency_country_map = {
                'USD': {'name': 'United States', 'alpha_2': 'US', 'alpha_3': 'USA'},
                'EUR': {'name': 'European Union', 'alpha_2': 'EU', 'alpha_3': 'EUR'},
                'GBP': {'name': 'United Kingdom', 'alpha_2': 'GB', 'alpha_3': 'GBR'},
                'NPR': {'name': 'Nepal', 'alpha_2': 'NP', 'alpha_3': 'NPL'},
                'AUD': {'name': 'Australia', 'alpha_2': 'AU', 'alpha_3': 'AUS'},
                'CAD': {'name': 'Canada', 'alpha_2': 'CA', 'alpha_3': 'CAN'},
                'INR': {'name': 'India', 'alpha_2': 'IN', 'alpha_3': 'IND'},
                'JPY': {'name': 'Japan', 'alpha_2': 'JP', 'alpha_3': 'JPN'},
                'CHF': {'name': 'Switzerland', 'alpha_2': 'CH', 'alpha_3': 'CHE'},
                'CNY': {'name': 'China', 'alpha_2': 'CN', 'alpha_3': 'CHN'},
                'SGD': {'name': 'Singapore', 'alpha_2': 'SG', 'alpha_3': 'SGP'},
                'HKD': {'name': 'Hong Kong', 'alpha_2': 'HK', 'alpha_3': 'HKG'},
                'KRW': {'name': 'South Korea', 'alpha_2': 'KR', 'alpha_3': 'KOR'},
                'THB': {'name': 'Thailand', 'alpha_2': 'TH', 'alpha_3': 'THA'},
                'MYR': {'name': 'Malaysia', 'alpha_2': 'MY', 'alpha_3': 'MYS'},
                'IDR': {'name': 'Indonesia', 'alpha_2': 'ID', 'alpha_3': 'IDN'},
                'PHP': {'name': 'Philippines', 'alpha_2': 'PH', 'alpha_3': 'PHL'},
                'VND': {'name': 'Vietnam', 'alpha_2': 'VN', 'alpha_3': 'VNM'},
                'BRL': {'name': 'Brazil', 'alpha_2': 'BR', 'alpha_3': 'BRA'},
                'MXN': {'name': 'Mexico', 'alpha_2': 'MX', 'alpha_3': 'MEX'},
                'ARS': {'name': 'Argentina', 'alpha_2': 'AR', 'alpha_3': 'ARG'},
                'CLP': {'name': 'Chile', 'alpha_2': 'CL', 'alpha_3': 'CHL'},
                'COP': {'name': 'Colombia', 'alpha_2': 'CO', 'alpha_3': 'COL'},
                'PEN': {'name': 'Peru', 'alpha_2': 'PE', 'alpha_3': 'PER'},
                'UYU': {'name': 'Uruguay', 'alpha_2': 'UY', 'alpha_3': 'URY'},
                'ZAR': {'name': 'South Africa', 'alpha_2': 'ZA', 'alpha_3': 'ZAF'},
                'EGP': {'name': 'Egypt', 'alpha_2': 'EG', 'alpha_3': 'EGY'},
                'NGN': {'name': 'Nigeria', 'alpha_2': 'NG', 'alpha_3': 'NGA'},
                'KES': {'name': 'Kenya', 'alpha_2': 'KE', 'alpha_3': 'KEN'},
                'GHS': {'name': 'Ghana', 'alpha_2': 'GH', 'alpha_3': 'GHA'},
                'UGX': {'name': 'Uganda', 'alpha_2': 'UG', 'alpha_3': 'UGA'},
                'TZS': {'name': 'Tanzania', 'alpha_2': 'TZ', 'alpha_3': 'TZA'},
                'RUB': {'name': 'Russia', 'alpha_2': 'RU', 'alpha_3': 'RUS'},
                'TRY': {'name': 'Turkey', 'alpha_2': 'TR', 'alpha_3': 'TUR'},
                'PLN': {'name': 'Poland', 'alpha_2': 'PL', 'alpha_3': 'POL'},
                'CZK': {'name': 'Czech Republic', 'alpha_2': 'CZ', 'alpha_3': 'CZE'},
                'HUF': {'name': 'Hungary', 'alpha_2': 'HU', 'alpha_3': 'HUN'},
                'SEK': {'name': 'Sweden', 'alpha_2': 'SE', 'alpha_3': 'SWE'},
                'NOK': {'name': 'Norway', 'alpha_2': 'NO', 'alpha_3': 'NOR'},
                'DKK': {'name': 'Denmark', 'alpha_2': 'DK', 'alpha_3': 'DNK'},
                'ISK': {'name': 'Iceland', 'alpha_2': 'IS', 'alpha_3': 'ISL'},
                'NZD': {'name': 'New Zealand', 'alpha_2': 'NZ', 'alpha_3': 'NZL'},
                'AED': {'name': 'United Arab Emirates', 'alpha_2': 'AE', 'alpha_3': 'ARE'},
                'SAR': {'name': 'Saudi Arabia', 'alpha_2': 'SA', 'alpha_3': 'SAU'},
                'QAR': {'name': 'Qatar', 'alpha_2': 'QA', 'alpha_3': 'QAT'},
                'KWD': {'name': 'Kuwait', 'alpha_2': 'KW', 'alpha_3': 'KWT'},
                'BHD': {'name': 'Bahrain', 'alpha_2': 'BH', 'alpha_3': 'BHR'},
                'OMR': {'name': 'Oman', 'alpha_2': 'OM', 'alpha_3': 'OMN'},
                'JOD': {'name': 'Jordan', 'alpha_2': 'JO', 'alpha_3': 'JOR'},
                'ILS': {'name': 'Israel', 'alpha_2': 'IL', 'alpha_3': 'ISR'},
            }

            # Currency symbols mapping
            currency_symbols = {
                'USD': '$', 'EUR': '€', 'GBP': '£', 'NPR': 'रू', 'AUD': 'A$', 'CAD': 'C$',
                'INR': '₹', 'JPY': '¥', 'CHF': 'CHF', 'CNY': '¥', 'SGD': 'S$', 'HKD': 'HK$',
                'KRW': '₩', 'THB': '฿', 'MYR': 'RM', 'IDR': 'Rp', 'PHP': '₱', 'VND': '₫',
                'BRL': 'R$', 'MXN': '$', 'ARS': '$', 'CLP': '$', 'COP': '$', 'PEN': 'S/',
                'UYU': '$', 'ZAR': 'R', 'EGP': 'E£', 'NGN': '₦', 'KES': 'KSh', 'GHS': 'GH₵',
                'UGX': 'USh', 'TZS': 'TSh', 'RUB': '₽', 'TRY': '₺', 'PLN': 'zł', 'CZK': 'Kč',
                'HUF': 'Ft', 'SEK': 'kr', 'NOK': 'kr', 'DKK': 'kr', 'ISK': 'kr', 'NZD': 'NZ$',
                'AED': 'د.إ', 'SAR': 'ر.س', 'QAR': 'ر.ق', 'KWD': 'د.ك', 'BHD': '.د.ب', 'OMR': 'ر.ع.',
                'JOD': 'د.ا', 'ILS': '₪',
            }

            currencies = []
            
            # Get only the top 50 currencies
            for currency in pycountry.currencies:
                currency_code = currency.alpha_3
                
                # Only include top 50 currencies
                if currency_code not in top_currencies:
                    continue
                
                # Get country info from our mapping
                country_info = None
                if currency_code in currency_country_map:
                    country_data = currency_country_map[currency_code]
                    country_info = {
                        'name': country_data['name'],
                        'alpha_2': country_data['alpha_2'],
                        'alpha_3': country_data['alpha_3'],
                        'flag_emoji': self._get_flag_emoji(country_data['alpha_2'])
                    }

                currencies.append({
                    'code': currency_code,
                    'name': currency.name,
                    'numeric': getattr(currency, 'numeric', None),
                    'symbol': currency_symbols.get(currency_code, currency_code),
                    'country': country_info
                })

            # Sort by the order in top_currencies list
            currencies.sort(key=lambda x: top_currencies.index(x['code']))
            
            return Response(currencies, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def _get_flag_emoji(self, country_code):
        """Convert country code to flag emoji."""
        if not country_code:
            return None
        
        # Convert country code to flag emoji
        try:
            # Convert to uppercase and get Unicode flag
            code = country_code.upper()
            flag = ''.join(chr(ord(c) + 127397) for c in code)
            return flag
        except:
            return None
