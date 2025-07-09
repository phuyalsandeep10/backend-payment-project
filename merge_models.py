#!/usr/bin/env python3
'''
Model Merge Helper Script
Run this after the initial merge to update models
'''

def merge_user_model():
    print("📋 To merge User model:")
    print("   cp ../merge_templates/user_model_merged.py backend/authentication/models.py")

def merge_settings():
    print("📋 To merge Settings:")
    print("   cp ../merge_templates/settings_merged.py backend/backend/settings.py")

def update_urls():
    print("📋 To update URLs, add these lines to backend/backend/urls.py:")
    print("   path('notifications/', include('notifications.urls')),")
    print("   path('dashboard/', include('Sales_dashboard.urls')),")
    print("   path('verifier/', include('Verifier_dashboard.urls')),")

if __name__ == "__main__":
    print("🚀 Manual merge steps:")
    print("=" * 50)
    merge_user_model()
    print()
    merge_settings()
    print()
    update_urls()
    print("=" * 50)
    print("💡 After applying changes, run:")
    print("   python manage.py makemigrations")
    print("   python manage.py migrate")
    print("   python manage.py runserver")
