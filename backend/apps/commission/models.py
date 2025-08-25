from decimal import Decimal
from django.db import models
from django.conf import settings
from apps.organization.models import Organization
import pycountry
from apps.deals.financial_optimizer import FinancialFieldOptimizer, FinancialValidationMixin
from apps.deals.atomic_operations import OptimisticLockingMixin

def get_currency_choices():
    return sorted([(c.alpha_3, f"{c.name} ({c.alpha_3})") for c in pycountry.currencies], key=lambda x: x[1])

class Commission(FinancialValidationMixin, OptimisticLockingMixin, models.Model):
    CURRENCY_CHOICES = get_currency_choices()
    
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
    
    # Optimistic locking version field
    lock_version = models.PositiveIntegerField(default=1, help_text="Version number for optimistic locking")

    def __str__(self):
        return f"Commission for {self.user.username} from {self.start_date} to {self.end_date}"

    # Frontend compatibility properties
    @property
    def full_name(self):
        return f"{self.user.first_name} {self.user.last_name}".strip() or self.user.username

    def _calculate_amounts(self):
        """
        Enhanced commission calculation using financial optimizer for precision
        """
        try:
            # Validate and normalize input values using financial optimizer
            commission_rate = FinancialFieldOptimizer.validate_commission_rate(
                self.commission_rate or Decimal("0")
            )
            total_sales = FinancialFieldOptimizer.validate_decimal_field(
                self.total_sales or Decimal("0"),
                'total_sales',
                precision=FinancialFieldOptimizer.CURRENCY_PRECISION
            )
            exchange_rate = FinancialFieldOptimizer.validate_exchange_rate(
                self.exchange_rate or Decimal("1")
            )
            bonus = FinancialFieldOptimizer.validate_decimal_field(
                self.bonus or Decimal("0"),
                'bonus',
                precision=FinancialFieldOptimizer.CURRENCY_PRECISION
            )
            penalty = FinancialFieldOptimizer.validate_decimal_field(
                self.penalty or Decimal("0"),
                'penalty',
                precision=FinancialFieldOptimizer.CURRENCY_PRECISION
            )
            
            # Calculate commission amount with proper decimal arithmetic
            self.commission_amount = FinancialFieldOptimizer.calculate_commission_amount(
                total_sales, commission_rate
            )
            
            # Calculate currency conversion
            converted_commission = FinancialFieldOptimizer.calculate_currency_conversion(
                self.commission_amount, exchange_rate
            )
            
            # Calculate total commission with bonus
            self.total_commission = converted_commission + bonus
            
            # Calculate total receivable after penalty
            self.total_receivable = self.total_commission - penalty
            
            # Calculate converted amount (total_sales * exchange_rate)
            self.converted_amount = FinancialFieldOptimizer.calculate_currency_conversion(
                total_sales, exchange_rate
            )
            
            # Ensure all amounts are properly rounded
            self.commission_amount = self.commission_amount.quantize(
                FinancialFieldOptimizer.CURRENCY_PRECISION
            )
            self.total_commission = self.total_commission.quantize(
                FinancialFieldOptimizer.CURRENCY_PRECISION
            )
            self.total_receivable = self.total_receivable.quantize(
                FinancialFieldOptimizer.CURRENCY_PRECISION
            )
            self.converted_amount = self.converted_amount.quantize(
                FinancialFieldOptimizer.CURRENCY_PRECISION
            )
            
        except Exception as e:
            # Fallback to original calculation if financial optimizer fails
            import logging
            logger = logging.getLogger('commission')
            logger.warning(f"Financial optimizer failed for commission {self.id}: {str(e)}")
            
            # Original calculation as fallback
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

    class Meta:
        indexes = [
            # Organization-scoped queries optimization
            models.Index(fields=['organization', 'user']),
            models.Index(fields=['organization', 'start_date', 'end_date']),
            models.Index(fields=['organization', 'created_at']),
            
            # User-specific commission queries
            models.Index(fields=['user', 'start_date', 'end_date']),
            models.Index(fields=['user', 'created_at']),
            
            # Financial calculations optimization
            models.Index(fields=['organization', 'total_sales', 'created_at']),
            models.Index(fields=['organization', 'total_commission', 'created_at']),
            models.Index(fields=['organization', 'commission_rate']),
            
            # Time-based queries
            models.Index(fields=['start_date', 'end_date']),
            models.Index(fields=['created_at', 'organization']),
            models.Index(fields=['updated_at', 'organization']),
            
            # Currency and exchange rate queries
            models.Index(fields=['currency', 'organization']),
            models.Index(fields=['exchange_rate', 'created_at']),
            
            # Audit and tracking
            models.Index(fields=['created_by', 'organization']),
            models.Index(fields=['updated_by', 'updated_at']),
        ]
        ordering = ['-created_at']
        unique_together = ('user', 'organization', 'start_date', 'end_date')
        verbose_name = 'Commission'
        verbose_name_plural = 'Commissions'

    def save(self, *args, **kwargs):
        from django.db import transaction
        from .calculation_optimizer import CommissionAuditTrail, CommissionCalculationOptimizer
        
        with transaction.atomic():
            # Track changes for audit
            changes = {}
            is_new = self.pk is None
            
            if not is_new:
                # Get old values for comparison
                try:
                    old_instance = Commission.objects.get(pk=self.pk)
                    if old_instance.total_sales != self.total_sales:
                        changes['total_sales'] = {
                            'old': float(old_instance.total_sales),
                            'new': float(self.total_sales)
                        }
                    if old_instance.commission_rate != self.commission_rate:
                        changes['commission_rate'] = {
                            'old': float(old_instance.commission_rate),
                            'new': float(self.commission_rate)
                        }
                except Commission.DoesNotExist:
                    pass
            
            if not self.organization_id:
                # Ensure organization is set, assuming user has one.
                if self.user and hasattr(self.user, 'organization') and self.user.organization:
                    self.organization = self.user.organization
                elif self.created_by and hasattr(self.created_by, 'organization') and self.created_by.organization:
                    self.organization = self.created_by.organization

            self._calculate_amounts()
            super().save(*args, **kwargs)
            
            # Log the calculation for audit purposes
            try:
                calculation_type = 'create' if is_new else 'update'
                user = getattr(self, '_current_user', None)
                
                CommissionAuditTrail.log_commission_calculation(
                    commission=self,
                    calculation_type=calculation_type,
                    user=user,
                    changes=changes
                )
                
                # Invalidate related caches
                CommissionCalculationOptimizer.invalidate_commission_caches(
                    organization_id=self.organization_id,
                    user_id=self.user_id
                )
                
            except Exception as e:
                # Don't fail the save if audit logging fails
                import logging
                logger = logging.getLogger('commission')
                logger.error(f"Failed to log commission calculation: {str(e)}")
    
    def set_current_user(self, user):
        """Set the current user for audit logging"""
        self._current_user = user
