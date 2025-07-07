from uuid import uuid4
from decimal import Decimal
from django.db import models
from django.conf import settings
from django.core.validators import MinValueValidator
from clients.models import Client

class Payment(models.Model):
    """Stores individual payments made for a deal/client."""

    STATUS_PENDING = 'pending'
    STATUS_VERIFIED = 'verified'
    STATUS_REJECTED = 'rejected'

    STATUS_CHOICES = [
        (STATUS_PENDING, 'Pending'),
        (STATUS_VERIFIED, 'Verified'),
        (STATUS_REJECTED, 'Rejected'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name='payments')
    # Until a dedicated Deal model exists, we use client + sequence_number to differentiate instalments
    sequence_number = models.PositiveIntegerField(help_text="1=first, 2=second, ...")

    amount = models.DecimalField(max_digits=12, decimal_places=2, validators=[MinValueValidator(Decimal("0.01"))])
    currency = models.CharField(max_length=3, default='USD')
    payment_method = models.CharField(max_length=50, blank=True, null=True)

    receipt_file = models.FileField(upload_to='receipts/', blank=True, null=True)

    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default=STATUS_PENDING)
    verified_at = models.DateTimeField(null=True, blank=True)
    verified_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('client', 'sequence_number')
        ordering = ['created_at']

    def __str__(self):
        return f"Payment {self.sequence_number} for {self.client.client_name} - {self.status}"

    @property
    def organization(self):
        """Expose organization via related client for permissions logic."""
        return self.client.organization 