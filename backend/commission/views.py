from decimal import Decimal
from django.db.models import Sum, Q
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

            # Get all salespeople with their total sales annotated to eliminate N+1 queries
            salespeople = User.objects.filter(
                organization=organization,
                role__name__in=['Salesperson', 'Senior Salesperson']
            ).select_related('role').annotate(
                total_verified_sales=Sum(
                    'created_deals__deal_value',
                    filter=Q(created_deals__verification_status='verified')
                )
            )

            commission_data = []
            
            for salesperson in salespeople:
                # Use annotated value to avoid N+1 query
                total_sales = salesperson.total_verified_sales or Decimal('0.00')
                
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


class NationalityView(APIView):
    """Get all supported nationalities/countries for nationality selection."""
    permission_classes = []  # No permissions required - accessible to all users
    
    def get(self, request):
        """Return countries as nationalities with their details."""
        try:
            # Get popular nationalities first (based on business usage)
            popular_nationalities = [
                'US', 'GB', 'AU', 'CA', 'IN', 'NP', 'CN', 'JP', 'DE', 'FR',
                'IT', 'ES', 'NL', 'BR', 'MX', 'RU', 'ZA', 'EG', 'NG', 'KE',
                'GH', 'UG', 'TZ', 'SG', 'HK', 'MY', 'TH', 'ID', 'PH', 'VN',
                'KR', 'TR', 'PL', 'CZ', 'HU', 'SE', 'NO', 'DK', 'FI', 'IS',
                'NZ', 'AE', 'SA', 'QA', 'KW', 'BH', 'OM', 'JO', 'IL', 'CH'
            ]
            
            # Nationality name mappings (demonym)
            nationality_names = {
                'AD': 'Andorran', 'AE': 'Emirati', 'AF': 'Afghan', 'AG': 'Antiguan', 'AI': 'Anguillan', 'AL': 'Albanian',
                'AM': 'Armenian', 'AO': 'Angolan', 'AR': 'Argentine', 'AS': 'American Samoan', 'AT': 'Austrian', 'AU': 'Australian',
                'AW': 'Aruban', 'AZ': 'Azerbaijani', 'BA': 'Bosnian', 'BB': 'Barbadian', 'BD': 'Bangladeshi', 'BE': 'Belgian',
                'BF': 'Burkinabé', 'BG': 'Bulgarian', 'BH': 'Bahraini', 'BI': 'Burundian', 'BJ': 'Beninese', 'BM': 'Bermudian',
                'BN': 'Bruneian', 'BO': 'Bolivian', 'BR': 'Brazilian', 'BS': 'Bahamian', 'BT': 'Bhutanese', 'BW': 'Botswanan',
                'BY': 'Belarusian', 'BZ': 'Belizean', 'CA': 'Canadian', 'CC': 'Cocos Islander', 'CD': 'Congolese', 'CF': 'Central African',
                'CG': 'Congolese', 'CH': 'Swiss', 'CI': 'Ivorian', 'CK': 'Cook Islander', 'CL': 'Chilean', 'CM': 'Cameroonian',
                'CN': 'Chinese', 'CO': 'Colombian', 'CR': 'Costa Rican', 'CU': 'Cuban', 'CV': 'Cape Verdean', 'CW': 'Curaçaoan',
                'CX': 'Christmas Islander', 'CY': 'Cypriot', 'CZ': 'Czech', 'DE': 'German', 'DJ': 'Djiboutian', 'DK': 'Danish',
                'DM': 'Dominican', 'DO': 'Dominican', 'DZ': 'Algerian', 'EC': 'Ecuadorian', 'EE': 'Estonian', 'EG': 'Egyptian',
                'ER': 'Eritrean', 'ES': 'Spanish', 'ET': 'Ethiopian', 'FI': 'Finnish', 'FJ': 'Fijian', 'FK': 'Falkland Islander',
                'FM': 'Micronesian', 'FO': 'Faroese', 'FR': 'French', 'GA': 'Gabonese', 'GB': 'British', 'GD': 'Grenadian',
                'GE': 'Georgian', 'GF': 'French Guianese', 'GG': 'Guernsey', 'GH': 'Ghanaian', 'GI': 'Gibraltarian', 'GL': 'Greenlandic',
                'GM': 'Gambian', 'GN': 'Guinean', 'GP': 'Guadeloupean', 'GQ': 'Equatorial Guinean', 'GR': 'Greek', 'GT': 'Guatemalan',
                'GU': 'Guamanian', 'GW': 'Guinea-Bissauan', 'GY': 'Guyanese', 'HK': 'Hong Konger', 'HN': 'Honduran', 'HR': 'Croatian',
                'HT': 'Haitian', 'HU': 'Hungarian', 'ID': 'Indonesian', 'IE': 'Irish', 'IL': 'Israeli', 'IM': 'Manx',
                'IN': 'Indian', 'IO': 'British Indian Ocean Territory', 'IQ': 'Iraqi', 'IR': 'Iranian', 'IS': 'Icelandic', 'IT': 'Italian',
                'JE': 'Jersey', 'JM': 'Jamaican', 'JO': 'Jordanian', 'JP': 'Japanese', 'KE': 'Kenyan', 'KG': 'Kyrgyzstani',
                'KH': 'Cambodian', 'KI': 'I-Kiribati', 'KM': 'Comoran', 'KN': 'Kittitian', 'KP': 'North Korean', 'KR': 'South Korean',
                'KW': 'Kuwaiti', 'KY': 'Caymanian', 'KZ': 'Kazakhstani', 'LA': 'Laotian', 'LB': 'Lebanese', 'LC': 'Saint Lucian',
                'LI': 'Liechtensteiner', 'LK': 'Sri Lankan', 'LR': 'Liberian', 'LS': 'Lesothan', 'LT': 'Lithuanian', 'LU': 'Luxembourgish',
                'LV': 'Latvian', 'LY': 'Libyan', 'MA': 'Moroccan', 'MC': 'Monégasque', 'MD': 'Moldovan', 'ME': 'Montenegrin',
                'MF': 'Saint-Martinoise', 'MG': 'Malagasy', 'MH': 'Marshallese', 'MK': 'Macedonian', 'ML': 'Malian', 'MM': 'Myanmar',
                'MN': 'Mongolian', 'MO': 'Macanese', 'MP': 'Northern Mariana Islander', 'MQ': 'Martinican', 'MR': 'Mauritanian', 'MS': 'Montserratian',
                'MT': 'Maltese', 'MU': 'Mauritian', 'MV': 'Maldivian', 'MW': 'Malawian', 'MX': 'Mexican', 'MY': 'Malaysian',
                'MZ': 'Mozambican', 'NA': 'Namibian', 'NC': 'New Caledonian', 'NE': 'Nigerien', 'NF': 'Norfolk Islander', 'NG': 'Nigerian',
                'NI': 'Nicaraguan', 'NL': 'Dutch', 'NO': 'Norwegian', 'NP': 'Nepali', 'NR': 'Nauruan', 'NU': 'Niuean',
                'NZ': 'New Zealander', 'OM': 'Omani', 'PA': 'Panamanian', 'PE': 'Peruvian', 'PF': 'French Polynesian', 'PG': 'Papua New Guinean',
                'PH': 'Filipino', 'PK': 'Pakistani', 'PL': 'Polish', 'PM': 'Saint-Pierrais', 'PR': 'Puerto Rican', 'PS': 'Palestinian',
                'PT': 'Portuguese', 'PW': 'Palauan', 'PY': 'Paraguayan', 'QA': 'Qatari', 'RE': 'Réunionese', 'RO': 'Romanian',
                'RS': 'Serbian', 'RU': 'Russian', 'RW': 'Rwandan', 'SA': 'Saudi Arabian', 'SB': 'Solomon Islander', 'SC': 'Seychellois',
                'SD': 'Sudanese', 'SE': 'Swedish', 'SG': 'Singaporean', 'SH': 'Saint Helenian', 'SI': 'Slovenian', 'SJ': 'Svalbard',
                'SK': 'Slovak', 'SL': 'Sierra Leonean', 'SM': 'Sammarinese', 'SN': 'Senegalese', 'SO': 'Somali', 'SR': 'Surinamese',
                'SS': 'South Sudanese', 'ST': 'São Toméan', 'SV': 'Salvadoran', 'SX': 'Sint Maartener', 'SY': 'Syrian', 'SZ': 'Swazi',
                'TC': 'Turks and Caicos Islander', 'TD': 'Chadian', 'TG': 'Togolese', 'TH': 'Thai', 'TJ': 'Tajikistani', 'TK': 'Tokelauan',
                'TL': 'Timorese', 'TM': 'Turkmen', 'TN': 'Tunisian', 'TO': 'Tongan', 'TR': 'Turkish', 'TT': 'Trinidadian',
                'TV': 'Tuvaluan', 'TW': 'Taiwanese', 'TZ': 'Tanzanian', 'UA': 'Ukrainian', 'UG': 'Ugandan', 'US': 'American',
                'UY': 'Uruguayan', 'UZ': 'Uzbekistani', 'VA': 'Vatican', 'VC': 'Vincentian', 'VE': 'Venezuelan', 'VG': 'British Virgin Islander',
                'VI': 'U.S. Virgin Islander', 'VN': 'Vietnamese', 'VU': 'Vanuatuan', 'WF': 'Wallisian', 'WS': 'Samoan', 'YE': 'Yemeni',
                'YT': 'Mahoran', 'ZA': 'South African', 'ZM': 'Zambian', 'ZW': 'Zimbabwean'
            }
            
            nationalities = []
            all_countries = list(pycountry.countries)
            
            # Sort: popular nationalities first, then alphabetically by nationality name
            def sort_key(country):
                code = country.alpha_2
                nationality_name = nationality_names.get(code, country.name)
                if code in popular_nationalities:
                    return (0, popular_nationalities.index(code))
                return (1, nationality_name)
            
            sorted_countries = sorted(all_countries, key=sort_key)
            
            for country in sorted_countries:
                nationality_name = nationality_names.get(country.alpha_2, country.name)
                flag_emoji = self._get_flag_emoji(country.alpha_2)
                
                nationalities.append({
                    'country_name': country.name,
                    'nationality': nationality_name,
                    'alpha_2': country.alpha_2,
                    'alpha_3': country.alpha_3,
                    'numeric': getattr(country, 'numeric', None),
                    'flag_emoji': flag_emoji,
                    'is_popular': country.alpha_2 in popular_nationalities
                })
            
            return Response(nationalities, status=status.HTTP_200_OK)
            
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


class CountryCodesView(APIView):
    """Get all supported country codes with their calling codes."""
    permission_classes = []  # No permissions required - accessible to all users
    
    def get(self, request):
        """Return countries with their calling codes and details."""
        try:
            # Get popular countries first (based on business usage)
            popular_countries = [
                'US', 'GB', 'AU', 'CA', 'IN', 'NP', 'CN', 'JP', 'DE', 'FR',
                'IT', 'ES', 'NL', 'BR', 'MX', 'RU', 'ZA', 'EG', 'NG', 'KE',
                'GH', 'UG', 'TZ', 'SG', 'HK', 'MY', 'TH', 'ID', 'PH', 'VN',
                'KR', 'TR', 'PL', 'CZ', 'HU', 'SE', 'NO', 'DK', 'FI', 'IS',
                'NZ', 'AE', 'SA', 'QA', 'KW', 'BH', 'OM', 'JO', 'IL', 'CH'
            ]
            
            # Manual mapping for countries with calling codes
            calling_codes = {
                'AD': '+376', 'AE': '+971', 'AF': '+93', 'AG': '+1', 'AI': '+1', 'AL': '+355',
                'AM': '+374', 'AO': '+244', 'AR': '+54', 'AS': '+1', 'AT': '+43', 'AU': '+61',
                'AW': '+297', 'AZ': '+994', 'BA': '+387', 'BB': '+1', 'BD': '+880', 'BE': '+32',
                'BF': '+226', 'BG': '+359', 'BH': '+973', 'BI': '+257', 'BJ': '+229', 'BM': '+1',
                'BN': '+673', 'BO': '+591', 'BR': '+55', 'BS': '+1', 'BT': '+975', 'BW': '+267',
                'BY': '+375', 'BZ': '+501', 'CA': '+1', 'CC': '+61', 'CD': '+243', 'CF': '+236',
                'CG': '+242', 'CH': '+41', 'CI': '+225', 'CK': '+682', 'CL': '+56', 'CM': '+237',
                'CN': '+86', 'CO': '+57', 'CR': '+506', 'CU': '+53', 'CV': '+238', 'CW': '+599',
                'CX': '+61', 'CY': '+357', 'CZ': '+420', 'DE': '+49', 'DJ': '+253', 'DK': '+45',
                'DM': '+1', 'DO': '+1', 'DZ': '+213', 'EC': '+593', 'EE': '+372', 'EG': '+20',
                'ER': '+291', 'ES': '+34', 'ET': '+251', 'FI': '+358', 'FJ': '+679', 'FK': '+500',
                'FM': '+691', 'FO': '+298', 'FR': '+33', 'GA': '+241', 'GB': '+44', 'GD': '+1',
                'GE': '+995', 'GF': '+594', 'GG': '+44', 'GH': '+233', 'GI': '+350', 'GL': '+299',
                'GM': '+220', 'GN': '+224', 'GP': '+590', 'GQ': '+240', 'GR': '+30', 'GT': '+502',
                'GU': '+1', 'GW': '+245', 'GY': '+592', 'HK': '+852', 'HN': '+504', 'HR': '+385',
                'HT': '+509', 'HU': '+36', 'ID': '+62', 'IE': '+353', 'IL': '+972', 'IM': '+44',
                'IN': '+91', 'IO': '+246', 'IQ': '+964', 'IR': '+98', 'IS': '+354', 'IT': '+39',
                'JE': '+44', 'JM': '+1', 'JO': '+962', 'JP': '+81', 'KE': '+254', 'KG': '+996',
                'KH': '+855', 'KI': '+686', 'KM': '+269', 'KN': '+1', 'KP': '+850', 'KR': '+82',
                'KW': '+965', 'KY': '+1', 'KZ': '+7', 'LA': '+856', 'LB': '+961', 'LC': '+1',
                'LI': '+423', 'LK': '+94', 'LR': '+231', 'LS': '+266', 'LT': '+370', 'LU': '+352',
                'LV': '+371', 'LY': '+218', 'MA': '+212', 'MC': '+377', 'MD': '+373', 'ME': '+382',
                'MF': '+590', 'MG': '+261', 'MH': '+692', 'MK': '+389', 'ML': '+223', 'MM': '+95',
                'MN': '+976', 'MO': '+853', 'MP': '+1', 'MQ': '+596', 'MR': '+222', 'MS': '+1',
                'MT': '+356', 'MU': '+230', 'MV': '+960', 'MW': '+265', 'MX': '+52', 'MY': '+60',
                'MZ': '+258', 'NA': '+264', 'NC': '+687', 'NE': '+227', 'NF': '+672', 'NG': '+234',
                'NI': '+505', 'NL': '+31', 'NO': '+47', 'NP': '+977', 'NR': '+674', 'NU': '+683',
                'NZ': '+64', 'OM': '+968', 'PA': '+507', 'PE': '+51', 'PF': '+689', 'PG': '+675',
                'PH': '+63', 'PK': '+92', 'PL': '+48', 'PM': '+508', 'PR': '+1', 'PS': '+970',
                'PT': '+351', 'PW': '+680', 'PY': '+595', 'QA': '+974', 'RE': '+262', 'RO': '+40',
                'RS': '+381', 'RU': '+7', 'RW': '+250', 'SA': '+966', 'SB': '+677', 'SC': '+248',
                'SD': '+249', 'SE': '+46', 'SG': '+65', 'SH': '+290', 'SI': '+386', 'SJ': '+47',
                'SK': '+421', 'SL': '+232', 'SM': '+378', 'SN': '+221', 'SO': '+252', 'SR': '+597',
                'SS': '+211', 'ST': '+239', 'SV': '+503', 'SX': '+1', 'SY': '+963', 'SZ': '+268',
                'TC': '+1', 'TD': '+235', 'TG': '+228', 'TH': '+66', 'TJ': '+992', 'TK': '+690',
                'TL': '+670', 'TM': '+993', 'TN': '+216', 'TO': '+676', 'TR': '+90', 'TT': '+1',
                'TV': '+688', 'TW': '+886', 'TZ': '+255', 'UA': '+380', 'UG': '+256', 'US': '+1',
                'UY': '+598', 'UZ': '+998', 'VA': '+39', 'VC': '+1', 'VE': '+58', 'VG': '+1',
                'VI': '+1', 'VN': '+84', 'VU': '+678', 'WF': '+681', 'WS': '+685', 'YE': '+967',
                'YT': '+262', 'ZA': '+27', 'ZM': '+260', 'ZW': '+263'
            }
            
            countries = []
            all_countries = list(pycountry.countries)
            
            # Sort: popular countries first, then alphabetically
            def sort_key(country):
                code = country.alpha_2
                if code in popular_countries:
                    return (0, popular_countries.index(code))
                return (1, country.name)
            
            sorted_countries = sorted(all_countries, key=sort_key)
            
            for country in sorted_countries:
                calling_code = calling_codes.get(country.alpha_2, '')
                flag_emoji = self._get_flag_emoji(country.alpha_2)
                
                countries.append({
                    'name': country.name,
                    'alpha_2': country.alpha_2,
                    'alpha_3': country.alpha_3,
                    'numeric': getattr(country, 'numeric', None),
                    'calling_code': calling_code,
                    'flag_emoji': flag_emoji,
                    'is_popular': country.alpha_2 in popular_countries
                })
            
            return Response(countries, status=status.HTTP_200_OK)
            
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
