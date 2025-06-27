from decimal import Decimal
from django.db import models
from django.conf import settings
from django.core.validators import MinValueValidator
from organization.models import Organization

class Commission(models.Model):
    organization = models.ForeignKey(
        Organization, on_delete=models.CASCADE, related_name='commissions'
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='commissions'
    )
    total_sales = models.DecimalField(max_digits=12, decimal_places=2)
    start_date = models.DateField()
    end_date = models.DateField()

    # Backend calculated fields
    commission_percentage = models.DecimalField(
        max_digits=5, decimal_places=2, default=Decimal('5.00')
    )
    converted_amount = models.DecimalField(
        max_digits=10, decimal_places=2, blank=True, null=True
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Commission for {self.user.username} from {self.start_date} to {self.end_date}"

    def calculate_commission(self):
        """
        Calculates the commission amount based on total sales and percentage.
        """
        if self.total_sales and self.commission_percentage:
            self.converted_amount = self.total_sales * (
                self.commission_percentage / Decimal("100")
            )

    def save(self, *args, **kwargs):
        if not self.organization_id:
            self.organization = self.user.organization
        self.calculate_commission()
        super().save(*args, **kwargs)
