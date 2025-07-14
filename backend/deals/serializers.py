from rest_framework import serializers
from decimal import Decimal
from .models import Deal, Payment, ActivityLog, PaymentInvoice, PaymentApproval
from authentication.serializers import UserLiteSerializer
from clients.serializers import ClientLiteSerializer
from clients.models import Client

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
            logger.warning(f"Error getting payment status for payment {obj.id}: {e}")
            return 'pending'
    
    def get_verified_amount(self, obj):
        """Get the verified amount from the latest approval"""
        try:
            latest_approval = obj.approvals.order_by('-approval_date').first()
            if latest_approval and latest_approval.amount_in_invoice and latest_approval.amount_in_invoice > 0:
                return latest_approval.amount_in_invoice
        except:
            pass
        return obj.received_amount
    
    def get_verified_by(self, obj):
        """Get the verifier information from the latest approval"""
        try:
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
            latest_approval = obj.approvals.order_by('-approval_date').first()
            return latest_approval.verifier_remarks if latest_approval else None
        except:
            return None
    
    def get_version(self, obj):
        """Get version number for the payment"""
        return 1  # Default version for payments

    def validate(self, data):
        print("DEBUG: validate method called with data:", data)
        
        # Validate required fields
        required_fields = ['payment_date', 'received_amount', 'cheque_number', 'payment_remarks']
        for field in required_fields:
            if field not in data or not data[field]:
                raise serializers.ValidationError(f"{field} is required")
        
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
            print("DEBUG: Received validated_data:", validated_data)
            
            # Handle deal_id as a direct field (frontend sends it directly)
            deal_id = validated_data.pop('deal_id', None)
            payment_category = validated_data.pop('payment_category', 'partial')
            
            print("DEBUG: deal_id:", deal_id)
            print("DEBUG: payment_category:", payment_category)
            
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
            
            # Calculate total amount already paid for this deal (using verified amounts when available)
            total_paid = 0
            for payment in deal.payments.all():
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

            print("DEBUG: Final validated_data:", validated_data)

            # Try to create the payment and catch any validation errors
            try:
                payment = Payment.objects.create(**validated_data)
            except Exception as e:
                print("DEBUG: Payment.objects.create failed with error:", str(e))
                print("DEBUG: Error type:", type(e))
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
            print("DEBUG: Exception occurred:", str(e))
            print("DEBUG: Exception type:", type(e))
            import traceback
            print("DEBUG: Full traceback:", traceback.format_exc())
            raise serializers.ValidationError(f"Unexpected error: {str(e)}")

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
    payments = serializers.SerializerMethodField()
    activity_logs = ActivityLogSerializer(many=True, read_only=True)

    # Aliases expected by FE table
    client_name = serializers.CharField(source='client.client_name', read_only=True)
    pay_status = serializers.CharField(source='payment_status', read_only=True)
    
    # Payment tracking fields
    total_paid = serializers.SerializerMethodField()
    remaining_balance = serializers.SerializerMethodField()
    payment_progress = serializers.SerializerMethodField()

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
            'total_paid', 'remaining_balance', 'payment_progress'
        ]
        read_only_fields = [
            'organization', 'deal_id', 'created_by', 'updated_by'
        ]

    def get_payments(self, obj):
        """Get payments ordered by creation date to ensure correct First/Second/Third order"""
        payments = obj.payments.all().order_by('created_at')
        return PaymentSerializer(payments, many=True, context=self.context).data
    
    def get_total_paid(self, obj):
        return obj.get_total_paid_amount()
    
    def get_remaining_balance(self, obj):
        return obj.get_remaining_balance()
    
    def get_payment_progress(self, obj):
        return obj.get_payment_progress()

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
            logger.warning(f"Error getting payment status for payment {obj.id}: {e}")
            return 'pending'
    
    def get_verified_by(self, obj):
        """Get the name of the person who verified this specific payment"""
        try:
            # Get the latest approval for this payment
            latest_approval = obj.approvals.order_by('-approval_date').first()
            if latest_approval and latest_approval.approved_by:
                return latest_approval.approved_by.get_full_name()
            
            # Fallback to deal's updated_by if no approval exists
            if obj.deal.updated_by:
                return obj.deal.updated_by.get_full_name()
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