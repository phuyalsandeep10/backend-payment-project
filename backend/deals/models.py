from django.db import models
import uuid
from organization.models import Organization
from django.conf import settings
from .validators import validate_file_security
from PIL import Image
from django.core.files.base import ContentFile
import io
import os

##
##  Deals Section
##
class Deal(models.Model):
    PAY_STATUS_CHOICES = [        ('initial payment','Initial Payment'),
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
    
    SOURCE_TYPES = [
        ('linkedin', 'LinkedIn'),
        ('instagram', 'Instagram'),
        ('google','Google'),
        ('referral','Referral'),
        ('others','Others')
    ]
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, unique=True )
    deal_id = models.CharField(max_length=50)
    organization = models.ForeignKey(Organization,on_delete=models.CASCADE,related_name="deals")
    client_name = models.CharField(max_length=255)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name='created_deals')
    pay_status = models.CharField(max_length=50, choices=PAY_STATUS_CHOICES)
    source_type = models.CharField(max_length=50,choices=SOURCE_TYPES)
    deal_value = models.DecimalField(max_digits=15,decimal_places=2)
    deal_date = models.DateField()
    due_date = models.DateField()
    payment_method = models.CharField(max_length=100,choices=PAYMENT_METHOD_CHOICES)
    deal_remarks = models.TextField(blank=True,null=True)
    deal_status = models.CharField(max_length=100,choices=DEAL_STATUS,default='pending')
    
    
    def __str__(self):
        return f"{self.deal_id} - {self.client_name}"
    
    class Meta:
        unique_together = ('organization','deal_id')
        
    def save(self,*args,**kwargs):
        if not self.deal_id:
            last_deal = Deal.objects.filter(organization = self.organization,deal_id__startswith='DLID').order_by("-deal_id").first()
            
            if last_deal:
                last_number = int(last_deal.deal_id[4:])
                new_number = last_number + 1
                
            else:
                new_number = 1
                
            self.deal_id = f"DLID{new_number:04d}"    #zero padded to 4 digits... fro eg. DLID0001\
        super().save(*args,**kwargs)
    
    
##
##   Payments Section
##

class Payment(models.Model):
    PAYMENT_TYPE = [
        ('partial_payment','Partial Payment'),
        ('full_payment','Full Payment'),
    ]
    
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
    cheque_number = models.CharField(max_length=50)
    payment_type = models.CharField(max_length=50)
    
    
    
    def __str__(self):
        return f"payment for {self.deal.deal_id} on {self.payment_date}"
    
    def save(self, *args, **kwargs):
        # Enhanced image compression with security checks
        if self.receipt_file and self.receipt_file.size > 1024 * 1024: # 1MB
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

##creates a activity log
def logactivity(deal,message):
    ActivityLog.objects.create(deal = deal , message = message)
    