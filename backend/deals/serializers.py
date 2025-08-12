from rest_framework import serializers
from decimal import Decimal
from .models import Deal, Payment, ActivityLog, PaymentInvoice, PaymentApproval
from authentication.serializers import UserLiteSerializer
from clients.serializers import ClientLiteSerializer
from clients.models import Client
from django.apps import apps
from django.core.exceptions import ValidationError

class ActivityLogSerializer(serializers.ModelSerializer):
    """
    Serializer for the ActivityLog model.
    """
    class Meta:
        model = ActivityLog
        fields = '__all__'

class PaymentSerializer(serializers.ModelSerializer):
    deal = serializers.PrimaryKeyRelatedField(read_only=True)
    deal_id = serializers.CharField(write_only=True)
    payment_type = serializers.CharField(read_only=True)
    payment_method = serializers.CharField(source='payment_type', read_only=True)  # Alias for frontend
    payment_category = serializers.CharField(write_only=True, required=False)
    status = serializers.SerializerMethodField()
    verified_amount = serializers.SerializerMethodField()
    verified_by = serializers.SerializerMethodField()
    verification_remarks = serializers.SerializerMethodField()
    version = serializers.SerializerMethodField()
    
    class Meta:
        model = Payment
        fields = [
            'id', 'transaction_id', 'deal', 'deal_id', 'payment_date', 
            'received_amount', 'cheque_number', 'payment_type', 'payment_method', 'payment_category',
            'payment_remarks', 'receipt_file', 'created_at', 'updated_at',
            'status', 'verified_amount', 'verified_by', 'verification_remarks', 'version'
        ]
        read_only_fields = ['id', 'transaction_id', 'created_at', 'updated_at', 'deal', 'payment_type', 'payment_method', 'status', 'verified_amount', 'verified_by', 'verification_remarks', 'version']
    
    def get_status(self, obj):
        """Get payment status from the related invoice or latest approval"""
        try:
            # Check if payment has been saved to database yet
            if not obj.pk:
                # Payment not saved yet, return default status
                return 'pending'
                
            # First try to get status from the invoice
            if hasattr(obj, 'invoice') and obj.invoice:
                return obj.invoice.invoice_status
            
            # If no invoice, check the latest approval
            latest_approval = obj.approvals.order_by('-approval_date').first()
            if latest_approval:
                if latest_approval.failure_remarks:
                    return 'rejected'
                else:
                    return 'verified'
            
            # Default to pending if no invoice or approval exists
            return 'pending'
        except Exception as e:
            # Log the error for debugging
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"Error getting payment status for payment {obj.pk or 'None'}: {e}")
            return 'pending'
    
    def get_verified_amount(self, obj):
        """Get the verified amount from the latest approval"""
        try:
            # Check if payment has been saved to database yet
            if not obj.pk:
                return obj.received_amount
                
            latest_approval = obj.approvals.order_by('-approval_date').first()
            if latest_approval and latest_approval.amount_in_invoice and latest_approval.amount_in_invoice > 0:
                return latest_approval.amount_in_invoice
        except:
            pass
        return obj.received_amount
    
    def get_verified_by(self, obj):
        """Get the verifier information from the latest approval - only for verified/rejected payments"""
        try:
            # Check if payment has been saved to database yet
            if not obj.pk:
                return None
                
            # First check if payment is actually verified/rejected
            payment_status = 'pending'
            if hasattr(obj, 'invoice') and obj.invoice:
                payment_status = obj.invoice.invoice_status
            else:
                latest_approval = obj.approvals.order_by('-approval_date').first()
                if latest_approval:
                    if latest_approval.failure_remarks:
                        payment_status = 'rejected'
                    else:
                        payment_status = 'verified'
            
            # Only return verifier info if payment is actually verified or rejected
            if payment_status in ['verified', 'rejected']:
                latest_approval = obj.approvals.order_by('-approval_date').first()
                if latest_approval and latest_approval.approved_by:
                    return {
                        'id': latest_approval.approved_by.id,
                        'full_name': latest_approval.approved_by.get_full_name() or latest_approval.approved_by.email,
                        'email': latest_approval.approved_by.email
                    }
        except:
            pass
        return None
    
    def get_verification_remarks(self, obj):
        """Get verification remarks from the latest approval"""
        try:
            # Check if payment has been saved to database yet
            if not obj.pk:
                return None
                
            latest_approval = obj.approvals.order_by('-approval_date').first()
            return latest_approval.verifier_remarks if latest_approval else None
        except:
            return None
    
    def get_version(self, obj):
        """Get version number for the payment"""
        return 1  # Default version for payments

    def validate(self, data):
        
        # Validate core required fields
        required_fields = ['payment_date', 'received_amount']
        for field in required_fields:
            if field not in data or not data[field]:
                raise serializers.ValidationError(f"{field} is required")
        
        # Conditional validation based on payment type
        payment_category = data.get('payment_category')
        payment_type = data.get('payment_type')
        
        # For deal context, check the deal's payment method if payment_type not provided
        if not payment_type and hasattr(self, 'context'):
            deal_id = data.get('deal_id')
            if deal_id:
                try:
                    from .models import Deal
                    request = self.context.get('request')
                    if request and hasattr(request, 'user') and request.user.organization:
                        deal = Deal.objects.get(deal_id=deal_id, organization=request.user.organization)
                        payment_type = deal.payment_method
                except:
                    pass
        
        # Require cheque_number for cheque payments
        if payment_type == 'cheque' or payment_category == 'cheque':
            if not data.get('cheque_number'):
                raise serializers.ValidationError({'cheque_number': 'Cheque number is required for cheque payments'})
        
        # Encourage payment_remarks for larger amounts or specific payment types
        received_amount = data.get('received_amount', 0)
        if isinstance(received_amount, str):
            try:
                received_amount = float(received_amount)
            except ValueError:
                received_amount = 0
        
        # Require payment_remarks for high-value transactions (>$10,000) or final payments
        if (received_amount > 10000 or payment_category == 'final') and not data.get('payment_remarks'):
            raise serializers.ValidationError({'payment_remarks': 'Payment remarks are required for high-value or final payments'})
        
        # Convert received_amount to decimal if it's a string
        if 'received_amount' in data and isinstance(data['received_amount'], str):
            try:
                data['received_amount'] = float(data['received_amount'])
            except ValueError:
                raise serializers.ValidationError("received_amount must be a valid number")
        
        return data

    def create(self, validated_data):
        try:
            # Debug: Log the received data
            
            # Handle deal_id as a direct field (frontend sends it directly)
            deal_id = validated_data.pop('deal_id', None)
            payment_category = validated_data.pop('payment_category', 'partial')
            
            
            if not deal_id:
                raise serializers.ValidationError("deal_id is required.")

            request = self.context.get('request')
            if not request or not hasattr(request, 'user'):
                 raise serializers.ValidationError("Request context is missing or user is not available.")

            organization = request.user.organization
            if not organization:
                raise serializers.ValidationError("User is not associated with an organization.")

            try:
                deal = Deal.objects.get(deal_id=deal_id, organization=organization)
            except Deal.DoesNotExist:
                raise serializers.ValidationError(f"Deal with ID {deal_id} not found in your organization.")

            # OVERPAYMENT VALIDATION
            received_amount = validated_data.get('received_amount', 0)
            if isinstance(received_amount, str):
                received_amount = float(received_amount)
            elif isinstance(received_amount, Decimal):
                received_amount = float(received_amount)
            
            # Calculate total amount already paid for this deal (only counting verified payments)
            total_paid = 0
            for payment in deal.payments.all():
                # Only count payments that are verified (not denied/rejected)
                payment_status = 'pending'
                try:
                    # First try to get status from the invoice
                    if hasattr(payment, 'invoice') and payment.invoice:
                        payment_status = payment.invoice.invoice_status
                    else:
                        # If no invoice, check the latest approval
                        latest_approval = payment.approvals.order_by('-approval_date').first()
                        if latest_approval:
                            if latest_approval.failure_remarks:
                                payment_status = 'rejected'
                            else:
                                payment_status = 'verified'
                except Exception:
                    payment_status = 'pending'
                
                # Only include verified payments in total
                if payment_status == 'verified':
                    # Get the verified amount if available, otherwise use received amount
                    try:
                        latest_approval = payment.approvals.order_by('-approval_date').first()
                        if latest_approval and latest_approval.amount_in_invoice and latest_approval.amount_in_invoice > 0:
                            total_paid += float(latest_approval.amount_in_invoice)
                        else:
                            total_paid += float(payment.received_amount)
                    except:
                        total_paid += float(payment.received_amount)
            
            deal_value = float(deal.deal_value)
            
            # Check if this payment would cause overpayment
            if total_paid + received_amount > deal_value:
                raise serializers.ValidationError(
                    f"Overpayment detected! Total paid: ${total_paid:.2f}, "
                    f"Deal value: ${deal_value:.2f}, "
                    f"This payment: ${received_amount:.2f}. "
                    f"Please edit the deal value first if overpayment is intended."
                )

            # Map payment category to payment type (method)
            payment_type_mapping = {
                'advance': 'wallet',
                'partial': 'bank', 
                'final': 'cash'
            }
            
            # Set the payment_type based on payment_category
            validated_data['payment_type'] = payment_type_mapping.get(payment_category, 'wallet')
            validated_data['payment_category'] = payment_category
            validated_data['deal'] = deal


            # Try to create the payment and catch any validation errors
            try:
                payment = Payment.objects.create(**validated_data)
            except Exception as e:
                raise serializers.ValidationError(f"Failed to create payment: {str(e)}")
            
            # Create activity log
            ActivityLog.objects.create(
                deal=deal,
                message=f"Payment of ${payment.received_amount} added by {request.user.get_full_name() or request.user.email}. "
                        f"Total paid: ${total_paid + received_amount:.2f}/{deal_value:.2f}"
            )
            
            return payment
            
        except serializers.ValidationError:
            # Re-raise validation errors
            raise
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Unexpected error in payment creation: {str(e)}")
            raise serializers.ValidationError(f"Unexpected error: {str(e)}")

class NestedPaymentSerializer(serializers.ModelSerializer):
    """Simplified payment serializer for nested use in DealSerializer"""
    payment_method = serializers.CharField(source='payment_type', required=False)  # Make it optional
    
    class Meta:
        model = Payment
        fields = [
            'payment_date', 'received_amount', 'cheque_number', 
            'payment_method', 'payment_remarks', 'receipt_file'
        ]
    
    def validate_cheque_number(self, value):
        """Validate that cheque number is unique within the organization"""
        if value:
            # Get the organization from the context (set in DealSerializer)
            organization = self.context.get('organization')
            if organization:
                # Check if this cheque number already exists in the organization
                Payment = apps.get_model('deals', 'Payment')
                if Payment.objects.filter(
                    deal__organization=organization,
                    cheque_number=value
                ).exists():
                    raise serializers.ValidationError(
                        f"Cheque number '{value}' already exists in your organization. Please use a different cheque number."
                    )
        return value

class DealSerializer(serializers.ModelSerializer):
    """
    Serializer for the Deal model, used for both read and write operations.
    """
    created_by = UserLiteSerializer(read_only=True)
    updated_by = UserLiteSerializer(read_only=True)
    client = ClientLiteSerializer(read_only=True)
    client_id = serializers.PrimaryKeyRelatedField(
        queryset=Client.objects.all(), source='client', write_only=True
    )
    payments = NestedPaymentSerializer(many=True, required=False, write_only=True)
    activity_logs = ActivityLogSerializer(many=True, read_only=True)

    def __init__(self, *args, **kwargs):
        """Override to handle FormData with nested payment fields"""
        super().__init__(*args, **kwargs)
        
        # Handle FormData parsing for nested payment fields
        if hasattr(self, 'initial_data') and self.initial_data:
            self._parse_formdata_payments()
    
    def _parse_formdata_payments(self):
        """Parse FormData where all fields come as arrays and handle nested payment structure"""
        if not hasattr(self, 'initial_data'):
            return
            
        
        # Convert QueryDict/FormData to regular dict and extract first value from arrays
        cleaned_data = {}
        payments_data = []
        payment_fields = {}
        
        for key, value in self.initial_data.items():
            # Handle Django QueryDict where values are lists, but exclude file uploads
            from django.core.files.uploadedfile import UploadedFile
            
            if isinstance(value, UploadedFile):
                # File uploads are not arrays - use directly
                cleaned_value = value
            elif hasattr(value, '__iter__') and not isinstance(value, (str, bytes)):
                # It's a list/array - take the first value
                cleaned_value = value[0] if len(value) > 0 else value
            else:
                cleaned_value = value
            
            # Check if it's a payment field
            if key.startswith('payments[0][') and key.endswith(']'):
                # Extract field name from payments[0][field_name]
                field_name = key[12:-1]  # Remove 'payments[0][' and ']'
                payment_fields[field_name] = cleaned_value
            else:
                # It's a regular deal field
                cleaned_data[key] = cleaned_value
        
        # If we found payment fields, add them to payments array
        if payment_fields:
            payments_data.append(payment_fields)
            cleaned_data['payments'] = payments_data
        else:
            pass
            
        # Handle client_name to client_id conversion
        if 'client_name' in cleaned_data and 'client_id' not in cleaned_data:
            client_name = cleaned_data['client_name']
            try:
                # Get the organization from context (should be set by the view)
                request = self.context.get('request')
                if request and hasattr(request, 'user') and request.user.organization:
                    client = Client.objects.get(
                        client_name=client_name, 
                        organization=request.user.organization
                    )
                    cleaned_data['client_id'] = client.id
            except Client.DoesNotExist:
                pass  # Let the validation handle this error
        
        
        # Replace initial_data with cleaned data
        self.initial_data = cleaned_data

    # Aliases expected by FE table
    client_name = serializers.CharField(source='client.client_name', read_only=True)
    pay_status = serializers.CharField(source='payment_status', read_only=True)
    
    # Payment tracking fields
    total_paid = serializers.SerializerMethodField()
    remaining_balance = serializers.SerializerMethodField()
    payment_progress = serializers.SerializerMethodField()
    
    # Add payments_read field for all users
    payments_read = serializers.SerializerMethodField()

    class Meta:
        model = Deal
        fields = [
            'id', 'deal_id', 'organization', 'client', 'client_id', 'created_by', 
            'updated_by', 'payment_status', 'verification_status', 'client_status', 'source_type', 
            'deal_value', 'deal_date', 'due_date', 'payment_method', 'deal_remarks', 
            'payments', 'activity_logs', 'version', 'deal_name', 'currency', 'created_at', 'updated_at',
            # Aliases
            'client_name', 'pay_status',
            # Payment tracking
            'total_paid', 'remaining_balance', 'payment_progress',
            # Payment details
            'payments_read'
        ]
        read_only_fields = [
            'id', 'deal_id', 'organization', 'created_by', 'updated_by', 
            'verification_status', 'client_status', 'created_at', 'updated_at',
            'client_name', 'pay_status', 'total_paid', 'remaining_balance', 'payment_progress', 'payments_read'
        ]

    def validate(self, data):
        """Validate deal data including payment consistency"""
        # Validate payment status vs first payment amount
        if 'payments' in data and data['payments']:
            first_payment = data['payments'][0]
            payment_status = data.get('payment_status')
            deal_value = data.get('deal_value')
            received_amount = first_payment.get('received_amount')
            
            if payment_status and deal_value and received_amount:
                deal_value_decimal = Decimal(str(deal_value))
                received_amount_decimal = Decimal(str(received_amount))
                
                if payment_status == 'full_payment':
                    # For full payment, received amount must equal deal value
                    if abs(deal_value_decimal - received_amount_decimal) > Decimal('0.01'):
                        raise serializers.ValidationError({
                            'payments': f'For full payment, received amount must equal deal value ({deal_value})'
                        })
                elif payment_status == 'partial_payment':
                    # For partial payment, received amount must be less than deal value
                    if received_amount_decimal >= deal_value_decimal:
                        raise serializers.ValidationError({
                            'payments': f'For partial payment, received amount must be less than deal value ({deal_value})'
                        })
                    if received_amount_decimal <= 0:
                        raise serializers.ValidationError({
                            'payments': 'Payment amount must be greater than 0'
                        })
        
        # Validate date logic
        deal_date = data.get('deal_date')
        due_date = data.get('due_date')
        if deal_date and due_date and deal_date > due_date:
            raise serializers.ValidationError({
                'due_date': 'Due date cannot be before deal date'
            })
        
        return data

    def create(self, validated_data):
        
        payments_data = validated_data.pop('payments', [])
        
        # Store payment data for model validation but don't pass it to create()
        payment_data_for_validation = None
        if payments_data:
            payment_data_for_validation = payments_data[0]
        
        # Create deal instance without _payment_data
        try:
            # Create the deal with validation
            deal = Deal(**validated_data)
            
            # Set payment data for validation if available
            if payment_data_for_validation:
                deal._payment_data = payment_data_for_validation
            
            # Run full_clean to trigger model validation including payment validation
            deal.full_clean()
            
            # Save the deal
            deal.save()
        except ValidationError as e:
            # Convert Django ValidationError to DRF ValidationError
            if hasattr(e, 'message_dict'):
                raise serializers.ValidationError(e.message_dict)
            raise serializers.ValidationError(str(e))
        except Exception as e:
            raise serializers.ValidationError(f"Unexpected error: {str(e)}")
        
        Payment = apps.get_model('deals', 'Payment')
        ActivityLog = apps.get_model('deals', 'ActivityLog')
        
        # Validate payments with organization context
        for payment_info in payments_data:
            # Create a temporary serializer instance to validate the payment data
            payment_serializer = NestedPaymentSerializer(
                data=payment_info,
                context={'organization': deal.organization}
            )
            if not payment_serializer.is_valid():
                # If validation fails, delete the deal and return the error
                deal.delete()
                raise serializers.ValidationError({
                    'payments': payment_serializer.errors
                })
        
        # Create payments
        for i, payment_info in enumerate(payments_data):
            try:
                
                payment = Payment.objects.create(
                    deal=deal,
                    payment_date=payment_info.get('payment_date'),
                    received_amount=payment_info.get('received_amount'),
                    cheque_number=payment_info.get('cheque_number', ''),
                    payment_type=payment_info.get('payment_method', deal.payment_method),  # Use deal's payment method if not specified
                    payment_remarks=payment_info.get('payment_remarks', ''),
                    receipt_file=payment_info.get('receipt_file'),  # Include receipt file
                )
                
                
                # Refresh from database to ensure we have the latest data
                payment.refresh_from_db()
                
                
                ActivityLog.objects.create(
                    deal=deal, 
                    message=f"Payment of {payment.received_amount} recorded."
                )
            except Exception as e:
                # If payment creation fails, delete the deal and return the error
                deal.delete()
                raise serializers.ValidationError({
                    'payments': f"Failed to create payment: {str(e)}"
                })
        
        # Debug: Check if payments are actually associated with the deal
        
        deal_payments = deal.payments.all()
        
        # for payment in deal_payments:
        #     pass  # TODO: Add payment processing logic if needed
        
        return deal

    def get_total_paid(self, obj):
        """Calculate total amount paid for this deal (only counting verified payments)"""
        total_paid = 0
        for payment in obj.payments.all():
            # Only count payments that are verified (not denied/rejected)
            payment_status = 'pending'
            try:
                # First try to get status from the invoice
                if hasattr(payment, 'invoice') and payment.invoice:
                    payment_status = payment.invoice.invoice_status
                else:
                    # If no invoice, check the latest approval
                    latest_approval = payment.approvals.order_by('-approval_date').first()
                    if latest_approval:
                        if latest_approval.failure_remarks:
                            payment_status = 'rejected'
                        else:
                            payment_status = 'verified'
            except Exception:
                payment_status = 'pending'
            
            # Only include verified payments in total
            if payment_status == 'verified':
                # Get the verified amount if available, otherwise use received amount
                try:
                    latest_approval = payment.approvals.order_by('-approval_date').first()
                    if latest_approval and latest_approval.amount_in_invoice and latest_approval.amount_in_invoice > 0:
                        total_paid += float(latest_approval.amount_in_invoice)
                    else:
                        total_paid += float(payment.received_amount)
                except:
                    total_paid += float(payment.received_amount)
        
        return total_paid
    
    def get_remaining_balance(self, obj):
        total_paid = self.get_total_paid(obj)
        return float(obj.deal_value) - total_paid
    
    def get_payment_progress(self, obj):
        total_paid = self.get_total_paid(obj)
        deal_value = float(obj.deal_value)
        return (total_paid / deal_value * 100) if deal_value > 0 else 0
    
    def get_payments_read(self, obj):
        """Get payments with proper prefetching and debug info"""
        
        if not obj.pk:
            return []
        
        payments = obj.payments.select_related('deal').prefetch_related('approvals', 'invoice').all()
        
        # for i, payment in enumerate(payments):
        #     pass  # TODO: Add payment processing logic if needed
        
        serialized_payments = PaymentSerializer(payments, many=True, context=self.context).data
        
        # for i, serialized_payment in enumerate(serialized_payments):
        #     pass  # TODO: Add serialized payment processing logic if needed
        
        return serialized_payments


class SalespersonDealSerializer(DealSerializer):
    """
    Extended DealSerializer for salesperson dashboard that includes payments_read field.
    """
    payments_read = serializers.SerializerMethodField()

    class Meta(DealSerializer.Meta):
        fields = DealSerializer.Meta.fields + ['payments_read']

    def get_payments_read(self, obj):
        return PaymentSerializer(obj.payments.all(), many=True).data

class DealPaymentHistorySerializer(serializers.ModelSerializer):
    """
    A serializer to represent a single payment record for the deal's expanded history view.
    """
    payment_serial = serializers.SerializerMethodField()
    payment_value = serializers.DecimalField(source='received_amount', max_digits=15, decimal_places=2)
    receipt_link = serializers.FileField(source='receipt_file', read_only=True)
    payment_version = serializers.CharField(source='deal.version', read_only=True)
    verification_status = serializers.SerializerMethodField()
    verified_by = serializers.SerializerMethodField()
    deal_remarks = serializers.CharField(source='deal.deal_remarks', read_only=True)
    verifier_remark_status = serializers.SerializerMethodField()

    class Meta:
        model = Payment
        fields = [
            'payment_serial', 'payment_date', 'created_at', 'payment_value',
            'receipt_link', 'payment_version', 'verification_status', 'verified_by',
            'deal_remarks', 'verifier_remark_status'
        ]

    def get_payment_serial(self, obj):
        # The serial number is passed via context from the parent serializer
        return self.context.get('serial_number', 0)
    
    def get_verification_status(self, obj):
        """Get payment status from the related invoice or latest approval"""
        try:
            # Check if payment has been saved to database yet
            if not obj.pk:
                return 'pending'
                
            # First try to get status from the invoice
            if hasattr(obj, 'invoice') and obj.invoice:
                return obj.invoice.invoice_status
            
            # If no invoice, check the latest approval
            latest_approval = obj.approvals.order_by('-approval_date').first()
            if latest_approval:
                if latest_approval.failure_remarks:
                    return 'rejected'
                else:
                    return 'verified'
            
            # Default to pending if no invoice or approval exists
            return 'pending'
        except Exception as e:
            # Log the error for debugging
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"Error getting payment status for payment {obj.pk or 'None'}: {e}")
            return 'pending'
    
    def get_verified_by(self, obj):
        """Get the name of the person who verified this specific payment - only for verified/rejected payments"""
        try:
            # Check if payment has been saved to database yet
            if not obj.pk:
                return None
                
            # First check if payment is actually verified/rejected
            payment_status = 'pending'
            if hasattr(obj, 'invoice') and obj.invoice:
                payment_status = obj.invoice.invoice_status
            else:
                latest_approval = obj.approvals.order_by('-approval_date').first()
                if latest_approval:
                    if latest_approval.failure_remarks:
                        payment_status = 'rejected'
                    else:
                        payment_status = 'verified'
            
            # Only return verifier info if payment is actually verified or rejected
            if payment_status in ['verified', 'rejected']:
                latest_approval = obj.approvals.order_by('-approval_date').first()
                if latest_approval and latest_approval.approved_by:
                    return latest_approval.approved_by.get_full_name()
            
            # Return None for pending payments (frontend should show "N/A")
            return None
        except:
            return None
    
    def get_verifier_remark_status(self, obj):
        """Get verifier remark status based on individual payment verification status"""
        payment_status = self.get_verification_status(obj)
        return "yes" if payment_status == 'verified' else "no"

class DealExpandedViewSerializer(serializers.ModelSerializer):
    """
    A serializer for the expanded deal view, providing detailed verification and payment history.
    """
    payment_history = serializers.SerializerMethodField()
    verified_by = serializers.CharField(source='updated_by.get_full_name', default=None, read_only=True)
    verifier_remark_status = serializers.SerializerMethodField()
    payment_version = serializers.CharField(source='version', read_only=True)

    class Meta:
        model = Deal
        fields = [
            'payment_history', 'verified_by', 'deal_remarks',
            'verifier_remark_status', 'payment_version','verification_status'
        ]

    def get_payment_history(self, obj):
        payments = obj.payments.all().order_by('created_at')
        # Pass the serial number to the child serializer via context
        return [
            DealPaymentHistorySerializer(p, context={'serial_number': i + 1}).data
            for i, p in enumerate(payments)
        ]

    def get_verifier_remark_status(self, obj):
        return "yes" if obj.verification_status == 'verified' else "no"

class DealUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Deal
        fields = [
            'id',
            'deal_id',
            'organization',
            'client',
            'project',
            'deal_name',
            'deal_value',
            'currency',
            'deal_date',
            'due_date',
            'payment_status',
            'payment_method',
            'source_type',
            'verification_status',
            'version',
            'created_by',
            'updated_by',
            'created_at',
            'updated_at',
        ]

class PaymentInvoiceSerializer(serializers.ModelSerializer):
    client_name = serializers.CharField(source='payment.deal.client.client_name', read_only=True)
    payment_amount = serializers.DecimalField(source='payment.received_amount', max_digits=15, decimal_places=2, read_only=True)

    
    class Meta:
        model = PaymentInvoice
        fields = [
            'id', 'payment', 'payment_amount','client_name',
            'invoice_id', 'invoice_date', 'due_date',
            'invoice_status', 'deal', 'receipt_file'
        ]

class PaymentApprovalSerializer(serializers.ModelSerializer):
    client_name = serializers.CharField(source='payment.invoice.deal.client.client_name', read_only=True)
    deal_id = serializers.CharField(source='payment.invoice.deal.deal_id', read_only=True)
    invoice_status = serializers.CharField(required=False)  # Make it writable for form submission
    payment_amount = serializers.DecimalField(source='payment.received_amount', max_digits=15, decimal_places=2, read_only=True)
    invoice_file = serializers.FileField(required=False, allow_null=True)
    invoice_id = serializers.CharField(source = 'payment.invoice.invoice_id', read_only=True)
    transaction_id = serializers.CharField(source='payment.transaction_id', read_only=True)
    failure_remarks_label = serializers.SerializerMethodField()
    
    class Meta:
        model = PaymentApproval
       
        fields = [
            'id',
            'payment_id',
            'deal',
            'deal_id',
            'client_name',
            'invoice_id',
            'invoice_status',
            'payment_amount',
            'invoice_file',
            'approved_by',
            'approval_date',
            'verifier_remarks',
            'failure_remarks',
            'failure_remarks_label',  # Add this field
            'amount_in_invoice',
            'transaction_id',
        ]
        
        read_only_fields = [
            'deal',
            'deal_id',
            'client_name',
            'payment',
            'payment_amount',
            'approval_date',
            'approved_by',
        ]

    def get_failure_remarks_label(self, obj):
        if obj.failure_remarks:
            return obj.get_failure_remarks_display()
        return None

    def create(self, validated_data):
        # Remove invoice_status from validated_data as it's not a field of PaymentApproval
        invoice_status = validated_data.pop('invoice_status', None)
        
        # Set failure_remarks based on invoice_status to work with the signal
        if invoice_status == 'rejected':
            # Use the failure_remarks from the request if provided, otherwise default to technical_error
            if 'failure_remarks' not in validated_data:
                validated_data['failure_remarks'] = 'technical_error'  # Default fallback
        elif invoice_status == 'verified':
            # Clear any existing failure_remarks
            validated_data['failure_remarks'] = None
        
        # Create the PaymentApproval instance
        approval = super().create(validated_data)
        
        # Update the invoice status directly as a backup to the signal
        if invoice_status and hasattr(approval.payment, 'invoice'):
            try:
                invoice = approval.payment.invoice
                invoice.invoice_status = invoice_status
                # Set a flag to skip the signal since we're manually updating
                invoice._skip_signal = True
                invoice.save()
            except Exception as e:
                pass  # Silently handle any errors
        
        # Update the deal verification status based on invoice status
        if invoice_status and hasattr(approval.payment, 'invoice'):
            deal = approval.payment.deal
            if invoice_status == 'verified':
                deal.verification_status = 'verified'
                # Update payment status to full_payment if amount matches deal value
                if approval.payment.received_amount >= deal.deal_value:
                    deal.payment_status = 'full_payment'
                else:
                    deal.payment_status = 'partial_payment'
            elif invoice_status == 'rejected':
                deal.verification_status = 'rejected'
            deal.save()
        
        return approval