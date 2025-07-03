from django.db import models
from django.conf import settings
from django.utils import timezone

# Create your models here.

class DailyStreakRecord(models.Model):
    """
    Tracks daily performance for streak calculation.
    """
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='streak_records')
    date = models.DateField()
    deals_closed = models.IntegerField(default=0)
    total_deal_value = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    streak_updated = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'date')
        ordering = ['-date']

    def __str__(self):
        return f"{self.user.username} - {self.date}: {self.deals_closed} deals, ${self.total_deal_value}"
