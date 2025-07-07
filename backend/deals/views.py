from rest_framework import viewsets
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.filters import SearchFilter, OrderingFilter
from django_filters.rest_framework import DjangoFilterBackend
from .serializers import DealSerializer
from .permissions import HasPermission
from clients.models import Client
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.utils import timezone
from django.db.models import Max
from rest_framework.decorators import action

from .models import Payment
from .serializers import PaymentSerializer

class DealCompatViewSet(viewsets.ModelViewSet):
    """
    Frontend compatibility viewset for flat deal access.
    Provides /deals/ endpoint instead of nested /clients/{id}/deals/
    """
    serializer_class = DealSerializer
    permission_classes = [AllowAny]
    parser_classes = [MultiPartParser, FormParser]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['status', 'category', 'satisfaction']
    search_fields = ['client_name', 'email']
    ordering_fields = ['created_at', 'value', 'updated_at']
    ordering = ['-created_at']
    queryset = Client.objects.all()

    def get_queryset(self):
        """Return clients filtered according to the authenticated user's organization and role."""
        user = self.request.user

        # Allow superusers to see everything
        if user and user.is_authenticated and user.is_superuser:
            return Client.objects.all()

        # Anonymous users should get nothing (or everything if AllowAny is desired)
        if not user or not user.is_authenticated:
            return Client.objects.none()

        # Users without an organization cannot see any clients
        if not user.organization:
            return Client.objects.none()

        base_qs = Client.objects.filter(organization=user.organization)

        # Org Admins can see all clients in their organization
        if user.role and user.role.name.lower().replace(' ', '').replace('-', '') in ['orgadmin', 'admin']:
            return base_qs

        # Users with explicit permission can view all clients
        if user.role and user.role.permissions.filter(codename='view_all_client').exists():
            return base_qs

        # Users with 'view_own_client_data' see only those they created / are salesperson for
        if user.role and user.role.permissions.filter(codename='view_own_client_data').exists():
            return base_qs.filter(created_by=user)
        
        # For salesperson role, show clients assigned to them
        if user.role and user.role.name.lower().replace(' ', '').replace('-', '') == 'salesperson':
            return base_qs.filter(salesperson=user)

        # Default: deny access
        return Client.objects.none()

class PaymentViewSet(viewsets.ModelViewSet):
    """CRUD for payments; includes custom verify action."""

    serializer_class = PaymentSerializer
    permission_classes = [HasPermission]
    queryset = Payment.objects.all()

    def get_queryset(self):
        qs = super().get_queryset()
        client_id = self.request.query_params.get('client_id')
        if client_id:
            qs = qs.filter(client_id=client_id)
        return qs

    def create(self, request, *args, **kwargs):
        """Assign sequence_number automatically if not provided."""
        data = request.data.copy()
        if 'sequence_number' not in data:
            client_id = data.get('client')
            if client_id:
                last_seq = (
                    Payment.objects.filter(client_id=client_id).aggregate(Max('sequence_number'))
                ).get('sequence_number__max') or 0
                data['sequence_number'] = last_seq + 1
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    @action(detail=True, methods=['post'])
    def verify(self, request, pk=None):
        """Verify or reject payment depending on 'status' in body."""
        payment = self.get_object()
        new_status = request.data.get('status')
        if new_status not in (Payment.STATUS_VERIFIED, Payment.STATUS_REJECTED):
            return Response({'error': 'Invalid status'}, status=status.HTTP_400_BAD_REQUEST)

        # Update fields
        payment.status = new_status
        payment.verified_at = timezone.now()
        if request.user.is_authenticated:
            payment.verified_by = request.user
        payment.save()

        # Notify salesperson (client created_by or hypothetical field)
        try:
            from authentication.models import Notification, User
            salesperson = payment.client.created_by  # assuming Client has created_by field
            if salesperson and isinstance(salesperson, User):
                Notification.objects.create(
                    user=salesperson,
                    title='Payment ' + ('verified' if new_status == Payment.STATUS_VERIFIED else 'rejected'),
                    message=f'Payment {payment.sequence_number} for client {payment.client.client_name} has been {new_status}.',
                    type='success' if new_status == Payment.STATUS_VERIFIED else 'error',
                )
        except Exception:
            # Silently ignore notification errors for now
            pass

        return Response(self.get_serializer(payment).data)

class PaymentVerificationView(APIView):
    """Compatibility wrapper that delegates to PaymentViewSet.verify."""
    permission_classes = [HasPermission]

    def post(self, request, payment_id):
        viewset = PaymentViewSet.as_view({'post': 'verify'})
        return viewset(request, pk=payment_id) 