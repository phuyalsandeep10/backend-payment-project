from django.contrib import admin
from .models import Deal, Payment, ActivityLog,PaymentInvoice, PaymentApproval

# Register your models here.

admin.site.register(Deal)
admin.site.register(Payment)
admin.site.register(ActivityLog)
admin.site.register(PaymentInvoice)
admin.site.register(PaymentApproval)
