"""
URL Configuration for Core Security Module

Task 2.2.1 - Core Config Decomposition
"""

from django.urls import path, include

app_name = 'security'

urlpatterns = [
    # Security monitoring and dashboard
    path('monitoring/', include('core.security.security_urls')),
    
    # File quarantine management
    path('quarantine/', include('core.security.quarantine_urls')),
]
