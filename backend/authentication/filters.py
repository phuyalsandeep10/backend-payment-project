import django_filters
from .models import User
from django.db.models import Q

class UserFilter(django_filters.FilterSet):
    """
    Filter for the User model.
    """
    full_name = django_filters.CharFilter(method='filter_by_full_name', label="Full Name")
    role = django_filters.CharFilter(method='filter_by_role', label="Role")

    class Meta:
        model = User
        fields = ['username', 'email', 'role']

    def filter_by_full_name(self, queryset, name, value):
        """
        Custom filter to search by full name (first name + last name).
        """
        return queryset.filter(
            Q(first_name__icontains=value) | Q(last_name__icontains=value)
        )

    def filter_by_role(self, queryset, name, value):
        """
        Custom filter to handle role name normalization.
        Maps frontend role names to backend role names.
        """
        if not value:
            return queryset
        
        # Normalize the input role name
        role_input = value.strip().lower()
        
        # Map frontend role names to backend role names
        role_mapping = {
            'org admin': 'Organization Admin',
            'org-admin': 'Organization Admin',
            'organization admin': 'Organization Admin',
            'salesperson': 'Salesperson',
            'verifier': 'Verifier',
            'supervisor': 'Supervisor',
            'team member': 'Team Member',
            'team-member': 'Team Member',
        }
        
        # Get the backend role name
        backend_role_name = role_mapping.get(role_input, value)
        
        # Filter by the backend role name
        return queryset.filter(role__name__iexact=backend_role_name) 