from django.contrib import admin
from .models import Clients

# Register your models here.
class ClientsAdmin(admin.ModelAdmin):
    list_display = ['client_name','email','phone_number','nationality']
    
admin.site.register(Clients,ClientsAdmin)