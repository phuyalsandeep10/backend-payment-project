from decimal import Decimal
from django.db import models
from django.conf import settings
from django.core.validators import MinValueValidator
from organization.models import Organization

class Commission(models.Model):
    CURRENCY_CHOICES = [
        ('NEP', 'Nepalese Rupee'),
        ('AUD', 'Australian Dollar'),
        ('USD', 'US Dollar'),
    ]
    
    organization = models.ForeignKey(
        Organization, on_delete=models.PROTECT, related_name='commissions'
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name='commissions'
    )
    
    # Core sales data
    total_sales = models.DecimalField(max_digits=12, decimal_places=2)
    start_date = models.DateField()
    end_date = models.DateField()

    # Commission calculation fields to match frontend expectations
    currency = models.CharField(max_length=3, choices=CURRENCY_CHOICES, default='USD')
    rate = models.DecimalField(max_digits=10, decimal_places=4, default=Decimal('1.0000'), help_text="Exchange rate")
    percentage = models.DecimalField(max_digits=5, decimal_places=2, default=Decimal('5.00'), help_text="Commission percentage")
    bonus = models.DecimalField(max_digits=10, decimal_places=2, default=Decimal('0.00'))
    penalty = models.DecimalField(max_digits=10, decimal_places=2, default=Decimal('0.00'))

    # Calculated fields
    converted_amount = models.DecimalField(max_digits=12, decimal_places=2, blank=True, null=True)
    total = models.DecimalField(max_digits=12, decimal_places=2, blank=True, null=True)
    total_receivable = models.DecimalField(max_digits=12, decimal_places=2, blank=True, null=True)

    # Legacy field for backward compatibility
    commission_percentage = models.DecimalField(
        max_digits=5, decimal_places=2, blank=True, null=True
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Commission for {self.user.username} from {self.start_date} to {self.end_date}"

    @property
    def full_name(self):
        """Full name property to match frontend expectations"""
        return f"{self.user.first_name} {self.user.last_name}".strip() or self.user.username

    @property
    def converted_amt(self):
        """Alias for converted_amount to match frontend expectations"""
        return self.converted_amount

    def calculate_commission(self):
        """
        Calculates the commission amount based on total sales and percentage.
        """
        if self.total_sales and self.percentage:
            # Convert sales to base currency
            self.converted_amount = self.total_sales * self.rate
            
            # Calculate commission
            commission_amount = self.converted_amount * (self.percentage / Decimal("100"))
            
            # Calculate total with bonus and penalty
            self.total = commission_amount + self.bonus - self.penalty
            
            # Total receivable is the same as total for now
            self.total_receivable = self.total
            
            # Update legacy field for backward compatibility
            self.commission_percentage = self.percentage

    def save(self, *args, **kwargs):
        if not self.organization_id:
            self.organization = self.user.organization
        self.calculate_commission()
        super().save(*args, **kwargs)
