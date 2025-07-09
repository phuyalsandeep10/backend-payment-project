from django.db import models
import uuid
from organization.models import Organization
from clients.models import Client
from django.conf import settings
from .validators import validate_file_security
from PIL import Image
from django.core.files.base import ContentFile
import io
import os
from django.utils import timezone
from project.models import Project
from django.db.models.signals import pre_save, post_save

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
        ('pending', 'Pending_Verification'),
        ('rejected', 'Rejected'),
    ]
    
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
    deal_id = models.CharField(max_length=50)
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
    
    
    def __str__(self):
        return f"{self.deal_id} - {self.client.name if self.client else ''}"
    
    class Meta:
        unique_together = ('organization','deal_id')
        permissions = [
            ("manage_invoices", "Can manage invoices"),
            ("access_verification_queue", "Can access verification queue"),
            ("verify_deal_payment", "Can verify deal payments"),
            ("manage_refunds", "Can manage refunds"),
            ("verify_payments", "Can verify payments"),
        ]
        
    def save(self,*args,**kwargs):
        is_new = self._state.adding
        if not self.deal_id:
            last_deal = Deal.objects.filter(organization = self.organization,deal_id__startswith='DLID').order_by("-deal_id").first()
            
            if last_deal:
                last_number = int(last_deal.deal_id[4:])
                new_number = last_number + 1
                
            else:
                new_number = 1
                
            self.deal_id = f"DLID{new_number:04d}"    #zero padded to 4 digits... fro eg. DLID0001\
        
        if not is_new:
            self.version = 'edited'

        super().save(*args,**kwargs)
    
    
##
##   Payments Section
##

class Payment(models.Model):
    PAYMENT_TYPE = [
        ('partial_payment','Partial Payment'),
        ('full_payment','Full Payment'),
    ]
    transaction_id = models.CharField(max_length=100, unique=True, blank=True, null=True)
    deal = models.ForeignKey(Deal,on_delete=models.CASCADE,related_name = 'payments')
    payment_date = models.DateField()
    receipt_file = models.FileField(
        upload_to='receipts/', 
        blank=True, 
        null=True,
        validators=[validate_file_security]
    )
    payment_remarks = models.TextField(blank=True,null=True)
    
    received_amount = models.DecimalField(max_digits=15,decimal_places=2)
    cheque_number = models.CharField(max_length=50, blank=True, null=True)
    payment_type = models.CharField(max_length=50, choices=Deal.PAYMENT_METHOD_CHOICES)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    
    def __str__(self):
        return f"payment for {self.deal.deal_id} on {self.payment_date}"
    
    def save(self, *args, **kwargs):
        # Validate cheque number for uniqueness before saving
        if self.cheque_number:
            # Check for other payments with the same cheque number within the same organization
            # This check is now more robust by scoping to the organization
            organization = self.deal.organization
            if Payment.objects.filter(
                deal__organization=organization,
                cheque_number=self.cheque_number
            ).exclude(pk=self.pk).exists():
                from django.core.exceptions import ValidationError
                raise ValidationError(f"Cheque number '{self.cheque_number}' has already been used in this organization.")
        
        if not self.transaction_id:
            last_transaction = Payment.objects.order_by('id').last()
            if last_transaction and last_transaction.transaction_id:
                last_id = int(last_transaction.transaction_id.split('-')[1])
                new_id = last_id + 1
                self.transaction_id = f'TXN-{new_id:04d}'
            else:
                self.transaction_id = 'TXN-0001'

        # Enhanced image compression with security checks
        if self.receipt_file and hasattr(self.receipt_file, 'size') and self.receipt_file.size > 1024 * 1024: # 1MB
            try:
                # Security: Verify file is actually an image before processing
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
                

            except Exception as e:
                # Security: Log the exception but don't expose details to user
                import logging
                logger = logging.getLogger('security')
                logger.warning(f"File processing error for payment {self.id}: {str(e)}")
                
                # Continue with save - validation will catch any real issues
                pass 
                
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
    receipt_file = models.FileField(upload_to='receipts/', null=True, blank=True)

    def __str__(self):
        return f"Invoice for {self.deal.deal_id} - {self.invoice_date}"

    def save(self, *args, **kwargs):
        user = kwargs.pop('user', None) # Pop user to avoid passing it to super().save()
        if not self.invoice_id:
            last_invoice = PaymentInvoice.objects.order_by('id').last()
            if last_invoice:
                last_id = int(last_invoice.invoice_id.split('-')[1])
                new_id = last_id + 1
                self.invoice_id = f'INV-{new_id:04d}'
            else:
                self.invoice_id = 'INV-0001'
        
        super(PaymentInvoice, self).save(*args, **kwargs)
    
    class Meta:
        ordering = ['-invoice_date']

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

    deal = models.ForeignKey(Deal, on_delete=models.CASCADE, related_name='approvals',blank=True,null=True)
    payment = models.ForeignKey(Payment, on_delete=models.CASCADE, related_name='approvals')
    invoice = models.ForeignKey(PaymentInvoice, on_delete=models.CASCADE, related_name='approvals', blank=True, null=True)
    approved_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name='payment_approvals')
    approval_date = models.DateField(auto_now_add=True)
    approved_remarks = models.TextField(blank=True, null=True)
    failure_remarks = models.CharField(max_length=50, choices=FAILURE_REMARKS, blank=True, null=True)
    amount_in_invoice = models.DecimalField(max_digits=15, decimal_places=2, default=0.00)
    def __str__(self):
        return f"Approval for {self.payment.deal.deal_id} - {self.approval_date}"
    def save(self, *args, **kwargs):
        if not self.deal and self.payment:
            self.deal = self.payment.deal
        
        super().save(*args, **kwargs)


















