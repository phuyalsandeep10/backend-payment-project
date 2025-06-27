import django_filters
from .models import User
from django.db.models import Q

class UserFilter(django_filters.FilterSet):
    """
    Filter for the User model.
    """
    full_name = django_filters.CharFilter(method='filter_by_full_name', label="Full Name")

    class Meta:
        model = User
        fields = ['username', 'email', 'org_role']

    def filter_by_full_name(self, queryset, name, value):
        """
        Custom filter to search by full name (first name + last name).
        """
        return queryset.filter(
            Q(first_name__icontains=value) | Q(last_name__icontains=value)
        ) 