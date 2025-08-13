from django.db import models
import uuid
import mimetypes
from organization.models import Organization
from clients.models import Client
from django.conf import settings
from core_config.file_security import validate_file_security_enhanced as validate_file_security
from PIL import Image
from django.core.files.base import ContentFile
import io
import os
from django.utils import timezone
from project.models import Project
from django.db.models.signals import pre_save, post_save
from django.core.exceptions import ValidationError
from decimal import Decimal

##
##  Deals Section
##
class Deal(models.Model):
    PAYMENT_STATUS_CHOICES = [        ('initial payment','Initial Payment'),
       ('partial_payment','Partial Payment'),
        ('full_payment','Full Payment'),
    ]
    
    PAYMENT_METHOD_CHOICES = [
        ('wallet', 'Mobile Wallet'),
        ('bank', 'Bank Transfer'),
        ('cheque', 'Cheque'),
        ('cash', 'Cash'),
    ]
    DEAL_STATUS = [
        ('verified', 'Verified'),
        ('pending', 'Pending'),
        ('rejected', 'Rejected'),
    ]
    
    # State machine: Valid transitions for verification_status
    VERIFICATION_STATUS_TRANSITIONS = {
        'pending': ['verified', 'rejected'],
        'verified': ['rejected'],  # Can reject verified deals if needed
        'rejected': [],  # No transitions from rejected (final state)
    }
    
    # State machine: Valid transitions for payment_status
    PAYMENT_STATUS_TRANSITIONS = {
        'initial payment': ['partial_payment', 'full_payment'],
        'partial_payment': ['full_payment'],
        'full_payment': [],  # Final state
    }
    
    VERSION_CHOICES = [
        ('original', 'Original'),
        ('edited', 'Edited'),
    ]
    
    SOURCE_TYPES = [
        ('linkedin', 'LinkedIn'),
        ('instagram', 'Instagram'),
        ('google','Google'),
        ('referral','Referral'),
        ('others','Others')
    ]
    CLIENT_STATUS = [
        ('pending', 'Pending'),
        ('loyal', 'Loyal'),
        ('bad_debt', 'Bad Debt'),
    ]
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, unique=True )
    deal_id = models.CharField(max_length=50, blank=True, db_index=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='deals')
    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name='deals')
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='deals', null=True, blank=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name='created_deals')
    updated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='updated_deals')
    payment_status = models.CharField(max_length=50, choices=PAYMENT_STATUS_CHOICES)
    source_type = models.CharField(max_length=50,choices=SOURCE_TYPES)
    deal_name = models.CharField(max_length=255, default='')
    deal_value = models.DecimalField(max_digits=10, decimal_places=2)
    currency = models.CharField(max_length=3, default='USD')
    deal_date = models.DateField(default=timezone.now)
    due_date = models.DateField(null=True, blank=True)
    payment_method = models.CharField(max_length=100,choices=PAYMENT_METHOD_CHOICES)
    deal_remarks = models.TextField(blank=True,null=True)
    verification_status = models.CharField(max_length=100,choices=DEAL_STATUS,default='pending')
    client_status = models.CharField(max_length=100,choices=CLIENT_STATUS,default='pending')
    version = models.CharField(max_length=10, choices=VERSION_CHOICES, default='original')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    payment_count = models.IntegerField(default=0, help_text="Number of payments made for this deal")
    
    
    def __str__(self):
        return f"{self.deal_id} - {self.client.client_name if self.client else ''}"
    
    class Meta:
        db_table = 'deals_deal'
        indexes = [
            models.Index(fields=['client', 'created_at']),
            models.Index(fields=['created_by', 'deal_date']),
            models.Index(fields=['payment_status', 'verification_status']),
            models.Index(fields=['due_date']),
            models.Index(fields=['deal_value']),
            # Performance critical indexes
            models.Index(fields=['organization', 'verification_status']),
            models.Index(fields=['organization', 'payment_status']),
            models.Index(fields=['source_type']),
            models.Index(fields=['organization', 'deal_date']),
            models.Index(fields=['organization', 'created_by']),
        ]
        ordering = ['-created_at']
        unique_together = ('organization','deal_id')
        permissions = [
            ("manage_invoices", "Can manage invoices"),
            ("access_verification_queue", "Can access verification queue"),
            ("verify_deal_payment", "Can verify deal payments"),
            ("manage_refunds", "Can manage refunds"),
            ("verify_payments", "Can verify payments"),
        ]
    
    def validate_verification_status_transition(self, new_status):
        """
        Validate that the verification status transition is allowed.
        Implements state machine pattern for deal lifecycle consistency.
        """
        if not self.verification_status:  # New deal
            return True
            
        current_status = self.verification_status
        allowed_transitions = self.VERIFICATION_STATUS_TRANSITIONS.get(current_status, [])
        
        if new_status not in allowed_transitions:
            from django.core.exceptions import ValidationError
            raise ValidationError(
                f"Invalid verification status transition from '{current_status}' to '{new_status}'. "
                f"Allowed transitions: {allowed_transitions}"
            )
        return True
    
    def validate_payment_status_transition(self, new_status):
        """
        Validate that the payment status transition is allowed.
        Implements state machine pattern for payment lifecycle consistency.
        """
        if not self.payment_status:  # New deal
            return True
            
        current_status = self.payment_status
        allowed_transitions = self.PAYMENT_STATUS_TRANSITIONS.get(current_status, [])
        
        if new_status not in allowed_transitions:
            from django.core.exceptions import ValidationError
            raise ValidationError(
                f"Invalid payment status transition from '{current_status}' to '{new_status}'. "
                f"Allowed transitions: {allowed_transitions}"
            )
        return True
    
    def can_transition_verification_status(self, new_status):
        """
        Check if verification status transition is allowed without raising exception.
        Returns True if transition is valid, False otherwise.
        """
        try:
            return self.validate_verification_status_transition(new_status)
        except ValidationError:
            return False
    
    def can_transition_payment_status(self, new_status):
        """
        Check if payment status transition is allowed without raising exception.
        Returns True if transition is valid, False otherwise.
        """
        try:
            return self.validate_payment_status_transition(new_status)
        except ValidationError:
            return False
        
    def save(self,*args,**kwargs):
        is_new = self._state.adding
        
        # State machine validation for existing deals
        if not is_new:
            try:
                # Get the current state from database
                current_deal = Deal.objects.get(pk=self.pk)
                
                # Validate verification status transition
                if current_deal.verification_status != self.verification_status:
                    self.validate_verification_status_transition(self.verification_status)
                
                # Validate payment status transition  
                if current_deal.payment_status != self.payment_status:
                    self.validate_payment_status_transition(self.payment_status)
                    
            except Deal.DoesNotExist:
                # Deal doesn't exist yet, skip validation
                pass
        
        if not self.deal_id:
            from django.db import transaction
            # Use select_for_update to prevent race conditions in ID generation
            with transaction.atomic():
                last_deal = Deal.objects.select_for_update().filter(
                    organization=self.organization,
                    deal_id__startswith='DLID'
                ).order_by("-deal_id").first()
                
                if last_deal:
                    last_number = int(last_deal.deal_id[4:])
                    new_number = last_number + 1
                else:
                    new_number = 1
                    
                self.deal_id = f"DLID{new_number:04d}"  # zero padded to 4 digits
        
        if not is_new:
            self.version = 'edited'

        super().save(*args,**kwargs)

    def get_total_paid_amount(self):
        """Calculate total amount paid for this deal (only counting verified payments)"""
        total_paid = 0
        for payment in self.payments.all():
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
    
    def get_remaining_balance(self):
        """Calculate remaining balance for this deal"""
        total_paid = self.get_total_paid_amount()
        return float(self.deal_value) - float(total_paid)
    
    def get_payment_progress(self):
        """Get payment progress as percentage"""
        total_paid = self.get_total_paid_amount()
        deal_value = float(self.deal_value)
        if deal_value == 0:
            return 0
        return (float(total_paid) / deal_value) * 100
    
    def clean(self):
        """Validate deal data including payment logic"""
        super().clean()
        
        # Validate deal_value is positive
        if self.deal_value is not None and self.deal_value <= 0:
            raise ValidationError({'deal_value': 'Deal value must be greater than 0'})
        
        # Validate date logic
        if self.deal_date and self.due_date and self.deal_date > self.due_date:
            raise ValidationError({'due_date': 'Due date cannot be before deal date'})
        
        # Validate payment status consistency
        if hasattr(self, '_payment_data'):
            self._validate_payment_consistency()
    
    def _validate_payment_consistency(self):
        """Validate payment amount against deal value based on payment status"""
        if not hasattr(self, '_payment_data') or not self._payment_data:
            return
            
        payment_amount = Decimal(str(self._payment_data.get('received_amount', 0)))
        deal_value = Decimal(str(self.deal_value))
        
        if self.payment_status == 'full_payment':
            # For full payment, received amount should equal deal value
            if abs(deal_value - payment_amount) > Decimal('0.01'):
                raise ValidationError({
                    'received_amount': f'For full payment, received amount must equal deal value ({deal_value})'
                })
        elif self.payment_status == 'partial_payment':
            # For partial payment, received amount should be less than deal value
            if payment_amount >= deal_value:
                raise ValidationError({
                    'received_amount': f'For partial payment, received amount must be less than deal value ({deal_value})'
                })
            if payment_amount <= 0:
                raise ValidationError({
                    'received_amount': 'Payment amount must be greater than 0'
                })
    
    def validate_additional_payment(self, payment_amount):
        """Validate additional payments don't exceed deal value"""
        current_total = Decimal(str(self.get_total_paid_amount()))
        new_payment = Decimal(str(payment_amount))
        deal_value = Decimal(str(self.deal_value))
        
        total_after_payment = current_total + new_payment
        
        if total_after_payment > deal_value:
            remaining = deal_value - current_total
            raise ValidationError(
                f'Payment amount ({new_payment}) would exceed deal value. '
                f'Maximum allowed: {remaining} (Remaining balance)'
            )
        
        return True
    
    
##
##   Payments Section
##



class Payment(models.Model):
    PAYMENT_TYPE = [
        ('partial_payment','Partial Payment'),
        ('full_payment','Full Payment'),
    ]
    
    PAYMENT_CATEGORY_CHOICES = [
        ('advance', 'Advance Payment'),
        ('partial', 'Partial Payment'),
        ('final', 'Final Payment'),
    ]
    
    transaction_id = models.CharField(max_length=100, unique=True, blank=True, null=True)
    deal = models.ForeignKey(Deal,on_delete=models.CASCADE,related_name = 'payments')
    payment_date = models.DateField()
    receipt_file = models.FileField(
        upload_to='receipts/',
        null=True,
        blank=True,
        validators=[validate_file_security]
    )
    payment_remarks = models.TextField(blank=True,null=True)
    
    received_amount = models.DecimalField(max_digits=15,decimal_places=2)
    cheque_number = models.CharField(max_length=50, blank=True, null=True)
    payment_type = models.CharField(max_length=50, choices=Deal.PAYMENT_METHOD_CHOICES)
    payment_category = models.CharField(max_length=50, choices=PAYMENT_CATEGORY_CHOICES, default='partial')
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'deals_payment'
        indexes = [
            models.Index(fields=['deal', 'payment_date']),
            models.Index(fields=['created_at']),
            models.Index(fields=['received_amount']),
        ]
        ordering = ['-payment_date']
        permissions = [
            ("create_deal_payment", "Can create deal payment"),
        ]

    def __str__(self):
        return f"payment for {self.deal.deal_id} on {self.payment_date}"
    
    def clean(self):
        """Validate payment data"""
        super().clean()
        
        # Validate received amount is positive
        if self.received_amount is not None and self.received_amount <= 0:
            raise ValidationError({'received_amount': 'Payment amount must be greater than 0'})
        
        # Allow back-dated entries for business needs (e.g., recording delayed payments)
        # Only restrict extremely old dates (more than 1 year ago) to prevent data entry errors
        if self.payment_date:
            from datetime import timedelta
            one_year_ago = timezone.now().date() - timedelta(days=365)
            if self.payment_date < one_year_ago:
                raise ValidationError({'payment_date': 'Payment date cannot be more than one year in the past'})
        
        # Validate payment doesn't exceed deal value for additional payments
        if self.deal_id and self.received_amount:
            try:
                self.deal.validate_additional_payment(self.received_amount)
            except ValidationError as e:
                raise ValidationError({'received_amount': str(e)})
    
    def save(self, *args, **kwargs):
        from django.db import transaction
        
        
        with transaction.atomic():
            # Validate cheque number for uniqueness before saving
            if self.cheque_number:
                # Check for other payments with the same cheque number within the same organization
                # This check is now more robust by scoping to the organization
                organization = self.deal.organization
                if Payment.objects.select_for_update().filter(
                    deal__organization=organization,
                    cheque_number=self.cheque_number
                ).exclude(pk=self.pk).exists():
                    from django.core.exceptions import ValidationError
                    raise ValidationError(f"Cheque number '{self.cheque_number}' has already been used in this organization.")
                else:
                    pass
            
            if not self.transaction_id:
                # Use select_for_update with proper ordering to prevent race conditions
                last_transaction = Payment.objects.select_for_update().filter(
                    transaction_id__startswith='TXN-'
                ).order_by('-id').first()
                
                if last_transaction and last_transaction.transaction_id:
                    try:
                        last_id = int(last_transaction.transaction_id.split('-')[1])
                        new_id = last_id + 1
                    except (ValueError, IndexError):
                        # Fallback if parsing fails
                        new_id = 1
                else:
                    new_id = 1
                
                self.transaction_id = f'TXN-{new_id:04d}'

            # Enhanced image compression with security checks - TEMPORARILY DISABLED FOR DEBUG
            if False and self.receipt_file and hasattr(self.receipt_file, 'size') and self.receipt_file.size > 1024 * 1024: # 1MB
                try:
                    # Security: Validate file before processing
                    # Note: validate_file_security is already called by the FileField validator
                    
                    # Additional security: Open image with verification
                    with Image.open(self.receipt_file) as img:
                        # Verify image integrity first
                        img.verify()
                    
                    # Reopen for processing (verify() closes the file)
                    img = Image.open(self.receipt_file)
                    
                    # Additional security: Check image format
                    if img.format.lower() not in ['jpeg', 'jpg', 'png']:
                        # If not a supported image format, don't process but allow save
                        # (other validation will catch non-image files)
                        super().save(*args, **kwargs)
                        return

                    # Check if it's an image that can be compressed
                    if img.format.lower() in ['jpeg', 'jpg', 'png']:
                        # Create a buffer to hold the compressed image
                        buffer = io.BytesIO()
                        
                        # Convert to RGB if necessary (for JPEG)
                        if img.mode in ['RGBA', 'P'] and img.format.lower() in ['jpeg', 'jpg']:
                            # Create a white background for transparency
                            background = Image.new('RGB', img.size, (255, 255, 255))
                            if img.mode == 'P':
                                img = img.convert('RGBA')
                            background.paste(img, mask=img.split()[-1] if img.mode == 'RGBA' else None)
                            img = background
                        
                        # Compress with quality optimization
                        quality = 85
                        if self.receipt_file.size > 5 * 1024 * 1024:  # If > 5MB, compress more
                            quality = 70
                            
                        # Save the image to the buffer with optimization
                        img.save(buffer, format=img.format, optimize=True, quality=quality)
                        
                        # Rewind the buffer
                        buffer.seek(0)
                        
                        # Create a new Django ContentFile
                        new_file = ContentFile(buffer.read())

                        # Get the original file name and extension
                        file_name, file_ext = os.path.splitext(self.receipt_file.name)
                        
                        # Save the compressed file
                        self.receipt_file.save(f"{file_name}_optimized{file_ext}", new_file, save=False)
                        
                        # Clean up
                        img.close()

                except Exception as e:
                    # Security: Log the exception but don't expose details to user
                    import logging
                    logger = logging.getLogger('security')
                    logger.warning(f"File processing error for payment {self.id}: {str(e)}")
                    
                    # Continue with save - validation will catch any real issues
                    pass 
                    
            # Complete the save operation within the atomic transaction
            super().save(*args, **kwargs)
    
    
##
##  Activity logs is used to record any changes made to deals model 
##
class ActivityLog(models.Model):
    deal = models.ForeignKey(Deal,on_delete=models.CASCADE,related_name="activity_logs")
    message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.timestamp} -- {self.message}"

##Payment Invoice Section (a payment invoice is created when a payment model is created.. signals.py handles this creation)
##
class PaymentInvoice(models.Model):
    payment = models.OneToOneField(Payment, on_delete=models.CASCADE, related_name='invoice')
    invoice_id = models.CharField(max_length=255, unique=True, blank=True)
    invoice_date = models.DateField(auto_now_add=True)
    due_date = models.DateField(null=True, blank=True)
    invoice_status = models.CharField(max_length=20, default='pending')
    deal = models.ForeignKey(Deal, on_delete=models.CASCADE, related_name='invoices')
    receipt_file = models.FileField(
        upload_to='receipts/', 
        null=True, 
        blank=True,
        validators=[validate_file_security]
    )

    def __str__(self):
        return f"Invoice for {self.deal.deal_id} - {self.invoice_date}"

    def save(self, *args, **kwargs):
        user = kwargs.pop('user', None) # Pop user to avoid passing it to super().save()
        if not self.invoice_id:
            from django.db import transaction
            # Use select_for_update to prevent race conditions in invoice ID generation
            with transaction.atomic():
                last_invoice = PaymentInvoice.objects.select_for_update().filter(
                    invoice_id__startswith='INV-'
                ).order_by('-id').first()
                
                if last_invoice and last_invoice.invoice_id:
                    try:
                        last_id = int(last_invoice.invoice_id.split('-')[1])
                        new_id = last_id + 1
                    except (ValueError, IndexError):
                        # Fallback if parsing fails
                        new_id = 1
                else:
                    new_id = 1
                
                self.invoice_id = f'INV-{new_id:04d}'
        
        super(PaymentInvoice, self).save(*args, **kwargs)
    
    class Meta:
        ordering = ['-invoice_date']
#added image compression for invoice file
class PaymentApproval(models.Model):
    FAILURE_REMARKS = [
        ('insufficient_funds', 'Insufficient Funds'),
        ('bank_decline', 'Bank Decline'),
        ('technical_error', 'Technical Error'),
        ('cheque_bounce', 'Cheque Bounce'),
        ('payment_received_not_reflected', 'Payment Received but not Reflected'),
    ]

    invoice_file = models.FileField(
        upload_to='invoices/',
        blank=True,
        null=True,
        validators=[validate_file_security]
    )
    deal = models.ForeignKey(Deal, on_delete=models.CASCADE, related_name='approvals', blank=True, null=True)
    payment = models.ForeignKey(Payment, on_delete=models.CASCADE, related_name='approvals')
    invoice = models.ForeignKey(PaymentInvoice, on_delete=models.CASCADE, related_name='approvals', blank=True, null=True)
    approved_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name='payment_approvals')
    approval_date = models.DateField(auto_now_add=True)
    verifier_remarks = models.TextField(blank=True, null=True)
    failure_remarks = models.CharField(max_length=50, choices=FAILURE_REMARKS, blank=True, null=True)
    amount_in_invoice = models.DecimalField(max_digits=15, decimal_places=2, default=0.00)

    def __str__(self):
        return f"Approval for {self.payment.deal.deal_id} - {self.approval_date}"

    def save(self, *args, **kwargs):
        if not self.deal and self.payment:
            self.deal = self.payment.deal

        # Image compression with file-type check
        if self.invoice_file and hasattr(self.invoice_file, 'size') and self.invoice_file.size > 1024 * 1024:
            try:
                # Early check for file type
                mime_type, _ = mimetypes.guess_type(self.invoice_file.name)
                if mime_type not in ['image/jpeg', 'image/png']:
                    # Not an image — skip compression, just save as-is
                    super().save(*args, **kwargs)
                    return

                # Open image safely
                img = Image.open(self.invoice_file)

                if img.format.lower() in ['jpeg', 'jpg', 'png']:
                    buffer = io.BytesIO()

                    if img.mode in ['RGBA', 'P'] and img.format.lower() in ['jpeg', 'jpg']:
                        background = Image.new('RGB', img.size, (255, 255, 255))
                        if img.mode == 'P':
                            img = img.convert('RGBA')
                        background.paste(img, mask=img.split()[-1] if img.mode == 'RGBA' else None)
                        img = background

                    quality = 85
                    if self.invoice_file.size > 5 * 1024 * 1024:
                        quality = 70

                    img.save(buffer, format=img.format, optimize=True, quality=quality)
                    buffer.seek(0)

                    new_file = ContentFile(buffer.read())
                    file_name, file_ext = os.path.splitext(self.invoice_file.name)
                    self.invoice_file.save(f"{file_name}_compressed{file_ext}", new_file, save=False)

            except Exception as e:
                import logging
                logger = logging.getLogger('security')
                logger.warning(f"Error compressing invoice file for PaymentApproval ID {self.id}: {str(e)}")
                # Save original file if error occurs
                pass

        super().save(*args, **kwargs)


# class PaymentApproval(models.Model):
#     FAILURE_REMARKS = [
#         ('insufficient_funds', 'Insufficient Funds'),
#         ('bank_decline', 'Bank Decline'),
#         ('technical_error', 'Technical Error'),
#         ('cheque_bounce', 'Cheque Bounce'),
#         ('payment_received_not_reflected', 'Payment Received but not Reflected'),
#     ]
#     invoice_file = models.FileField(
#         upload_to='invoices/',
#         blank=True,
#         null=True,
#         validators=[validate_file_security]
#     )

#     deal = models.ForeignKey(Deal, on_delete=models.CASCADE, related_name='approvals',blank=True,null=True)
#     payment = models.ForeignKey(Payment, on_delete=models.CASCADE, related_name='approvals')
#     invoice = models.ForeignKey(PaymentInvoice, on_delete=models.CASCADE, related_name='approvals', blank=True, null=True)
#     approved_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name='payment_approvals')
#     approval_date = models.DateField(auto_now_add=True)
#     approved_remarks = models.TextField(blank=True, null=True)
#     failure_remarks = models.CharField(max_length=50, choices=FAILURE_REMARKS, blank=True, null=True)
#     amount_in_invoice = models.DecimalField(max_digits=15, decimal_places=2, default=0.00)
#     def __str__(self):
#         return f"Approval for {self.payment.deal.deal_id} - {self.approval_date}"
#     def save(self, *args, **kwargs):
#         if not self.deal and self.payment:
#             self.deal = self.payment.deal
        
        
#         super().save(*args, **kwargs)


















