from decimal import Decimal
from django.db import models
from django.conf import settings
from organization.models import Organization

class Commission(models.Model):
    CURRENCY_CHOICES = [
        ('NPR', 'Nepalese Rupee'),
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
    total_sales = models.DecimalField(max_digits=15, decimal_places=2, default=Decimal('0.00'))
    start_date = models.DateField()
    end_date = models.DateField()

    # Commission calculation inputs
    currency = models.CharField(max_length=3, choices=CURRENCY_CHOICES, default='USD')
    commission_rate = models.DecimalField(
        "Commission Rate (%)", max_digits=5, decimal_places=2, default=Decimal("5.00")
    )
    exchange_rate = models.DecimalField(max_digits=10, decimal_places=2, default=Decimal('1.00'))
    bonus = models.DecimalField(max_digits=15, decimal_places=2, default=Decimal('0.00'))
    penalty = models.DecimalField(max_digits=10, decimal_places=2, default=Decimal('0.00'))

    # Backend calculated fields
    commission_amount = models.DecimalField(
        max_digits=10, decimal_places=2, blank=True, default=Decimal('0.00')
    )
    total_commission = models.DecimalField(
        max_digits=12, decimal_places=2, blank=True, default=Decimal('0.00')
    )
    total_receivable = models.DecimalField(
        max_digits=12, decimal_places=2, blank=True, default=Decimal('0.00')
    )
    converted_amount = models.DecimalField(
        max_digits=12, decimal_places=2, blank=True, default=Decimal('0.00')
    )
    
    # Audit fields
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_commissions'
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='updated_commissions'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Commission for {self.user.username} from {self.start_date} to {self.end_date}"

    # Frontend compatibility properties
    @property
    def full_name(self):
        return f"{self.user.first_name} {self.user.last_name}".strip() or self.user.username

    def _calculate_amounts(self):
        """
        Calculates commission amounts based on sales and other inputs.
        """
        commission_rate = self.commission_rate or Decimal("0")
        total_sales = self.total_sales or Decimal("0")
        self.commission_amount = total_sales * (commission_rate / Decimal("100"))

        exchange_rate = self.exchange_rate or Decimal("1")
        bonus = self.bonus or Decimal("0")
        self.total_commission = (exchange_rate * self.commission_amount) + bonus

        penalty = self.penalty or Decimal("0")
        self.total_receivable = self.total_commission - penalty
        
        # Calculate converted amount (total_sales * exchange_rate)
        self.converted_amount = total_sales * exchange_rate

    def save(self, *args, **kwargs):
        if not self.organization_id:
            # Ensure organization is set, assuming user has one.
            if self.user and hasattr(self.user, 'organization') and self.user.organization:
                self.organization = self.user.organization
            elif self.created_by and hasattr(self.created_by, 'organization') and self.created_by.organization:
                self.organization = self.created_by.organization

        self._calculate_amounts()
        super().save(*args, **kwargs)
