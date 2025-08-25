
# ===================== USER VIEWSET DOCUMENTATION =====================

from rest_framework import viewsets
from core_config.enhanced_swagger_config import document_viewset_actions

@document_viewset_actions(
    tags=['User Management'],
    operation_id_base='users'
)
class UserViewSet(viewsets.ModelViewSet):
    """
    User management ViewSet with full CRUD operations.
    
    Provides endpoints for:
    - Listing users (with filtering and pagination)
    - Retrieving individual user details
    - Creating new users (admin only)
    - Updating user information
    - Deleting users (admin only)
    
    **Permissions**: 
    - List/Retrieve: Authenticated users (filtered by organization)
    - Create/Update/Delete: Admin users only
    
    **Filtering**: 
    - Search by name or email
    - Filter by role, organization, active status
    - Order by name, email, date_joined
    """
    
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['role', 'is_active', 'organization']
    search_fields = ['first_name', 'last_name', 'email']
    ordering_fields = ['first_name', 'last_name', 'email', 'date_joined']
    ordering = ['last_name', 'first_name']
    
    # The @document_viewset_actions decorator automatically adds
    # appropriate swagger documentation to all CRUD methods
