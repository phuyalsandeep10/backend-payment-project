from django.db import models

class Organization(models.Model):
    """
    Model to represent an organization.
    """
    name = models.CharField(max_length=255, unique=True)
    is_active = models.BooleanField(default=True)
    sales_goal = models.DecimalField(max_digits=15, decimal_places=2, default=100000.00)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Organization'
        verbose_name_plural = 'Organizations'
