from rest_framework import viewsets, status, filters, serializers
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import get_object_or_404
from django_filters.rest_framework import DjangoFilterBackend
from django.db.models import Q
from django.utils import timezone
from .models import Deal, Payment, ActivityLog, PaymentInvoice, PaymentApproval
from apps.deals.serializers import (
    DealSerializer, SalespersonDealSerializer, PaymentSerializer, ActivityLogSerializer, DealExpandedViewSerializer,
    PaymentInvoiceSerializer, PaymentApprovalSerializer
)
from .permissions import HasPermission
from rest_framework.response import Response
from rest_framework.decorators import action
from core.performance.database_optimizer import QueryOptimizer, QueryMonitor, OptimizedQueryMixin

class DealViewSet(OptimizedQueryMixin, viewsets.ModelViewSet):
    """
    A viewset for managing Deals, with granular permission checks and optimized queries.
    """
    serializer_class = DealSerializer
    permission_classes = [HasPermission]
    lookup_field = 'deal_id'
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['client', 'payment_status', 'verification_status', 'source_type', 'payment_method']
    search_fields = ['deal_id', 'deal_name', 'client__client_name']
    ordering_fields = ['deal_date', 'due_date', 'deal_value', 'created_at']
    ordering = ['-created_at']

    def get_serializer_class(self):
        """
        Use SalespersonDealSerializer for salesperson users to include payments_read field.
        """
        # Handle swagger schema generation
        if getattr(self, 'swagger_fake_view', False):
            return DealSerializer
            
        user = self.request.user
        if hasattr(user, 'role') and user.role:
            role_name = user.role.name.strip().replace('-', ' ').lower()
            if 'salesperson' in role_name or 'sales' in role_name:
                return SalespersonDealSerializer
        return DealSerializer

    def get_queryset(self):
        """Enhanced query optimization using QueryOptimizer"""
        user = self.request.user
        organization = getattr(user, 'organization', None)
        
        if not organization:
            return Deal.objects.none()
        
        # Base queryset with organization filtering
        base_queryset = Deal.objects.filter(organization=organization)
        
        # Use QueryOptimizer for comprehensive optimization
        include_payments = 'payments' in self.request.query_params.get('include', '')
        optimized_queryset = QueryOptimizer.optimize_deal_queryset(
            base_queryset, 
            organization,
            include_payments=include_payments
        )
        
        return optimized_queryset

    def list(self, request, *args, **kwargs):
        """Enhanced list view with query monitoring and optimization"""
        with QueryMonitor.monitor_query("DealViewSet.list"):
            queryset = self.get_optimized_queryset()
            
            # Add filtering with indexed fields for better performance
            status = request.query_params.get('status')
            if status:
                queryset = queryset.filter(payment_status=status)
            
            verification_status = request.query_params.get('verification_status')
            if verification_status:
                queryset = queryset.filter(verification_status=verification_status)
            
            # Add search with indexed fields
            search = request.query_params.get('search')
            if search:
                queryset = queryset.filter(
                    Q(deal_name__icontains=search) |
                    Q(client__client_name__icontains=search) |
                    Q(deal_id__icontains=search)
                )
            
            # Add date range filtering
            start_date = request.query_params.get('start_date')
            end_date = request.query_params.get('end_date')
            if start_date:
                queryset = queryset.filter(deal_date__gte=start_date)
            if end_date:
                queryset = queryset.filter(deal_date__lte=end_date)
            
            page = self.paginate_queryset(queryset)
            if page is not None:
                serializer = self.get_serializer(page, many=True)
                return self.get_paginated_response(serializer.data)
            
            serializer = self.get_serializer(queryset, many=True)
            return Response(serializer.data)

    def create(self, request, *args, **kwargs):
        """Custom create method to handle FormData parsing"""
        import logging
        logger = logging.getLogger(__name__)
        
        # Parse FormData for nested payments before serialization
        data = request.data.copy() if hasattr(request.data, 'copy') else dict(request.data)
        
        # Make data mutable if it's a QueryDict
        if hasattr(data, '_mutable'):
            data._mutable = True
        
        logger.info(f"DealViewSet.create - request.data type: {type(request.data)}")
        logger.info(f"DealViewSet.create - data keys: {list(data.keys())}")
        
        # Parse nested payment fields
        payment_data = []
        payment_indices = set()
        
        # Find payment field indices
        for key in data.keys():
            if key.startswith('payments[') and '][' in key:
                try:
                    index = int(key.split('[')[1].split(']')[0])
                    payment_indices.add(index)
                except (ValueError, IndexError):
                    continue
        
        logger.info(f"Found payment indices: {payment_indices}")
        
        # Group fields by payment index
        for index in payment_indices:
            payment_item = {}
            prefix = f'payments[{index}]'
            
            for key in list(data.keys()):
                if key.startswith(prefix):
                    field_name = key.replace(f'{prefix}[', '').replace(']', '')
                    
                    if field_name:
                        # Get the value (handle both QueryDict and regular dict)
                        if hasattr(data, 'get'):
                            value = data.get(key)
                        else:
                            value = data[key]
                        
                        if value is not None and value != '':
                            payment_item[field_name] = value
                        
                        # Remove the original key to avoid conflicts
                        if key in data:
                            del data[key]
            
            if payment_item:
                payment_data.append(payment_item)
                logger.info(f"Payment item {index}: {payment_item}")
        
        # Add parsed payments to data
        if payment_data:
            # Create a custom data dict that combines QueryDict data with parsed payments
            if hasattr(data, '_mutable'):
                # Convert QueryDict to regular dict while preserving all data types
                combined_data = {}
                
                # Copy all non-payment fields from QueryDict
                for key in data.keys():
                    if not key.startswith('payments['):
                        combined_data[key] = data.get(key)
                
                # Add the parsed payments
                combined_data['payments'] = payment_data
                data = combined_data
                logger.info(f"Created combined data dict with payments: {len(payment_data)} payments")
            else:
                # For regular dict, just set the payments
                data['payments'] = payment_data
                logger.info(f"Added payments to regular dict: {payment_data}")
        
        # Use the modified data for serialization
        try:
            logger.info(f"About to create serializer with data keys: {list(data.keys())}")
            if 'payments' in data:
                logger.info(f"Payments data being passed to serializer: {data['payments']}")
            
            serializer = self.get_serializer(data=data)
            logger.info(f"Serializer created successfully")
            
            if not serializer.is_valid():
                logger.error(f"Serializer validation failed: {serializer.errors}")
                return Response({
                    'error': 'Validation failed',
                    'details': serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Save with organization and user info
            deal = serializer.save(
                organization=request.user.organization,
                created_by=request.user,
                updated_by=request.user
            )
            logger.info(f"Deal created successfully: {deal.deal_id}")
            
            # Create a simple response to avoid serialization issues
            response_data = {
                'id': str(deal.id),
                'deal_id': deal.deal_id,
                'deal_name': deal.deal_name,
                'deal_value': str(deal.deal_value),
                'payment_status': deal.payment_status,
                'message': 'Deal created successfully'
            }
            
            return Response(response_data, status=status.HTTP_201_CREATED)
            
        except serializers.ValidationError as e:
            logger.error(f"Validation error during deal creation: {str(e)}")
            
            # Extract detailed error information
            error_details = {}
            error_message = "Validation failed"
            
            if hasattr(e, 'detail') and e.detail:
                error_details = e.detail
                if isinstance(e.detail, dict):
                    # Field-specific errors
                    for field, messages in e.detail.items():
                        if isinstance(messages, list) and messages:
                            error_message = f"{field}: {messages[0]}"
                            break
                        elif messages:
                            error_message = f"{field}: {messages}"
                            break
                elif isinstance(e.detail, list) and e.detail:
                    error_message = str(e.detail[0])
                    error_details = {'errors': e.detail}
                else:
                    error_message = str(e.detail)
            else:
                error_message = str(e)
            
            # Return detailed validation error response
            return Response({
                'error': {
                    'code': 'VALIDATION_ERROR',
                    'message': error_message,
                    'details': error_details,
                    'timestamp': timezone.now().isoformat()
                }
            }, status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as e:
            logger.error(f"Error during deal creation: {str(e)}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return Response({
                'error': 'Failed to create deal',
                'details': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def update(self, request, *args, **kwargs):
        """Custom update method to handle FormData parsing"""
        import logging
        logger = logging.getLogger(__name__)
        
        # Get the existing deal instance
        instance = self.get_object()
        
        # Parse FormData for nested payments before serialization
        data = request.data.copy() if hasattr(request.data, 'copy') else dict(request.data)
        
        # Make data mutable if it's a QueryDict
        if hasattr(data, '_mutable'):
            data._mutable = True
        
        logger.info(f"DealViewSet.update - request.data type: {type(request.data)}")
        logger.info(f"DealViewSet.update - data keys: {list(data.keys())}")
        
        # Parse nested payment fields (reusing logic from create method)
        payment_data = []
        payment_indices = set()
        
        # Find payment field indices
        for key in data.keys():
            if key.startswith('payments[') and '][' in key:
                try:
                    index = int(key.split('[')[1].split(']')[0])
                    payment_indices.add(index)
                except (ValueError, IndexError):
                    continue
        
        logger.info(f"Found payment indices: {payment_indices}")
        
        # Group fields by payment index
        for index in payment_indices:
            payment_item = {}
            prefix = f'payments[{index}]'
            
            for key in list(data.keys()):
                if key.startswith(prefix):
                    field_name = key.replace(f'{prefix}[', '').replace(']', '')
                    
                    if field_name:
                        # Get the value (handle both QueryDict and regular dict)
                        if hasattr(data, 'get'):
                            value = data.get(key)
                        else:
                            value = data[key]
                        
                        if value is not None and value != '':
                            payment_item[field_name] = value
                        
                        # Remove the original key to avoid conflicts
                        if key in data:
                            del data[key]
            
            if payment_item:
                payment_data.append(payment_item)
                logger.info(f"Payment item {index}: {payment_item}")
        
        # Add parsed payments to data
        if payment_data:
            # Create a custom data dict that combines QueryDict data with parsed payments
            if hasattr(data, '_mutable'):
                # Convert QueryDict to regular dict while preserving all data types
                combined_data = {}
                
                # Copy all non-payment fields from QueryDict
                for key in data.keys():
                    if not key.startswith('payments['):
                        combined_data[key] = data.get(key)
                
                # Add the parsed payments
                combined_data['payments'] = payment_data
                data = combined_data
                logger.info(f"Created combined data dict with payments: {len(payment_data)} payments")
            else:
                # For regular dict, just set the payments
                data['payments'] = payment_data
                logger.info(f"Added payments to regular dict: {payment_data}")
        
        # Use the modified data for serialization
        try:
            logger.info(f"About to create serializer with data keys: {list(data.keys())}")
            if 'payments' in data:
                logger.info(f"Payments data being passed to serializer: {data['payments']}")
            
            partial = kwargs.pop('partial', False)
            serializer = self.get_serializer(instance, data=data, partial=partial)
            logger.info(f"Serializer created successfully")
            
            if not serializer.is_valid():
                logger.error(f"Serializer validation failed: {serializer.errors}")
                return Response({
                    'error': 'Validation failed',
                    'details': serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Save with user info
            deal = serializer.save(updated_by=request.user)
            logger.info(f"Deal updated successfully: {deal.deal_id}")
            
            # Create a simple response to avoid serialization issues
            response_data = {
                'id': str(deal.id),
                'deal_id': deal.deal_id,
                'deal_name': deal.deal_name,
                'deal_value': str(deal.deal_value),
                'payment_status': deal.payment_status,
                'message': 'Deal updated successfully'
            }
            
            return Response(response_data, status=status.HTTP_200_OK)
            
        except serializers.ValidationError as e:
            logger.error(f"Validation error during deal update: {str(e)}")
            
            # Extract detailed error information
            error_details = {}
            error_message = "Validation failed"
            
            if hasattr(e, 'detail') and e.detail:
                error_details = e.detail
                if isinstance(e.detail, dict):
                    # Field-specific errors
                    for field, messages in e.detail.items():
                        if isinstance(messages, list) and messages:
                            error_message = f"{field}: {messages[0]}"
                            break
                        elif messages:
                            error_message = f"{field}: {messages}"
                            break
                elif isinstance(e.detail, list) and e.detail:
                    error_message = str(e.detail[0])
                    error_details = {'errors': e.detail}
                else:
                    error_message = str(e.detail)
            else:
                error_message = str(e)
            
            # Return detailed validation error response
            return Response({
                'error': {
                    'code': 'VALIDATION_ERROR',
                    'message': error_message,
                    'details': error_details,
                    'timestamp': timezone.now().isoformat()
                }
            }, status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as e:
            logger.error(f"Error during deal update: {str(e)}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return Response({
                'error': 'Failed to update deal',
                'details': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def perform_create(self, serializer):
        serializer.save(
            organization=self.request.user.organization,
            created_by=self.request.user,
            updated_by=self.request.user
        )

    def perform_update(self, serializer):
        serializer.save(updated_by=self.request.user)

    @action(detail=True, methods=['get'], url_path='expand', serializer_class=DealExpandedViewSerializer)
    def expand(self, request, deal_id=None):
        """
        Provides an expanded view of a single deal, including detailed
        verification information and a full payment history.
        """
        deal = self.get_object()
        serializer = DealExpandedViewSerializer(deal)
        return Response(serializer.data)

    @action(detail=True, methods=['get'], url_path='log-activity', serializer_class=ActivityLogSerializer)
    def log_activity(self, request, deal_id=None):
        """
        Returns the activity log for a specific deal.
        """
        deal = self.get_object()
        activities = deal.activity_logs.all().order_by('-timestamp')
        serializer = self.get_serializer(activities, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['get'], url_path='invoices')
    def list_invoices(self, request, deal_id=None):
        deal = self.get_object()
        invoices = PaymentInvoice.objects.filter(deal=deal)
        serializer = PaymentInvoiceSerializer(invoices, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['get'], url_path='payments')
    def list_payments(self, request, deal_id=None):
        """
        Get all payments for this deal with their related invoices and approvals.
        """
        deal = self.get_object()
        payments = Payment.objects.filter(deal=deal).select_related(
            'deal', 'deal__client', 'deal__organization'
        ).prefetch_related(
            'invoice', 'approvals', 'approvals__approved_by'
        ).order_by('-payment_date')
        
        serializer = PaymentSerializer(payments, many=True)
        
        return Response({
            'deal': {
                'deal_id': deal.deal_id,
                'deal_name': deal.deal_name,
                'deal_value': deal.deal_value,
                'client_name': deal.client.client_name if deal.client else None,
            },
            'payments': serializer.data,
            'total_payments': payments.count(),
            'total_amount': sum(payment.received_amount for payment in payments)
        })

class PaymentViewSet(viewsets.ModelViewSet):
    """
    A viewset for managing Payments with support for filtering by deal ID.
    """
    serializer_class = PaymentSerializer
    permission_classes = [HasPermission]

    def get_queryset(self):
        # Prevent crash during schema generation
        if getattr(self, 'swagger_fake_view', False):
            return Payment.objects.none()
        
        user = self.request.user
        queryset = Payment.objects.select_related('deal', 'deal__organization', 'deal__client')
        
        # Filter by organization
        if user.is_superuser:
            pass  # Superuser can see all payments
        elif user.organization:
            queryset = queryset.filter(deal__organization=user.organization)
        else:
            return Payment.objects.none()
        
        # Filter by deal ID if provided in query params
        deal_id = self.request.query_params.get('deal_id', None)
        if deal_id:
            queryset = queryset.filter(deal__deal_id=deal_id)
        
        # Filter by deal UUID if provided in query params
        deal_uuid = self.request.query_params.get('deal', None)
        if deal_uuid:
            queryset = queryset.filter(deal_id=deal_uuid)
        
        return queryset

    def perform_create(self, serializer):
        serializer.save()

    @action(detail=False, methods=['get'], url_path='by-deal/(?P<deal_id>[^/.]+)')
    def by_deal(self, request, deal_id=None):
        """
        Get all payments for a specific deal with their related invoices and approvals.
        """
        try:
            # Find the deal by deal_id
            deal = get_object_or_404(Deal, deal_id=deal_id, organization=request.user.organization)
            
            # Get all payments for this deal with related data
            payments = Payment.objects.filter(deal=deal).select_related(
                'deal', 'deal__client', 'deal__organization'
            ).prefetch_related(
                'invoice', 'approvals', 'approvals__approved_by'
            ).order_by('-payment_date')
            
            # Serialize with expanded data
            serializer = PaymentSerializer(payments, many=True)
            
            return Response({
                'deal': {
                    'deal_id': deal.deal_id,
                    'deal_name': deal.deal_name,
                    'deal_value': deal.deal_value,
                    'client_name': deal.client.client_name if deal.client else None,
                },
                'payments': serializer.data,
                'total_payments': payments.count(),
                'total_amount': sum(payment.received_amount for payment in payments)
            })
            
        except Deal.DoesNotExist:
            return Response(
                {'error': f'Deal with ID {deal_id} not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {'error': f'Error retrieving payments: {str(e)}'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class ActivityLogViewSet(viewsets.ReadOnlyModelViewSet):
    """
    A read-only viewset for ActivityLogs related to a specific deal.
    """
    serializer_class = ActivityLogSerializer
    permission_classes = [HasPermission]

    def get_queryset(self):
        if getattr(self, 'swagger_fake_view', False):
            return ActivityLog.objects.none()
            
        deal_pk = self.kwargs.get('deal_pk')
        deal = get_object_or_404(Deal, pk=deal_pk)
        
        # The permission class already ensures the user can view the deal.
        return ActivityLog.objects.filter(deal=deal).order_by('-timestamp')

class PaymentInvoiceViewSet(viewsets.ModelViewSet):
    queryset = PaymentInvoice.objects.all()
    serializer_class = PaymentInvoiceSerializer
    permission_classes = [HasPermission]
    lookup_field = 'invoice_id'  # Use invoice_id instead of id

    def get_queryset(self):
        # Prevent crash during schema generation
        if getattr(self, 'swagger_fake_view', False):
            return PaymentInvoice.objects.none()
        
        # Filter by the organization of the logged-in user
        if self.request.user.is_authenticated and hasattr(self.request.user, 'organization'):
            return PaymentInvoice.objects.filter(deal__organization=self.request.user.organization)
        
        return PaymentInvoice.objects.none()

class PaymentApprovalViewSet(viewsets.ModelViewSet):
    queryset = PaymentApproval.objects.all()
    serializer_class = PaymentApprovalSerializer
    permission_classes = [HasPermission]

    def get_queryset(self):
        # Prevent crash during schema generation
        if getattr(self, 'swagger_fake_view', False):
            return PaymentApproval.objects.none()
        
        # Filter by the organization of the logged-in user
        if self.request.user.is_authenticated and hasattr(self.request.user, 'organization'):
            return PaymentApproval.objects.filter(deal__organization=self.request.user.organization)
        
        return PaymentApproval.objects.none()


class ChunkedFileUploadView(APIView):
    """
    Handle chunked file uploads for large receipts and invoices.
    Optimizes server performance by processing files in chunks.
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        import os
        import tempfile
        from django.core.files.base import ContentFile
        from django.core.files.storage import default_storage
        
        try:
            # Get upload parameters
            chunk_number = int(request.data.get('chunk_number', 0))
            total_chunks = int(request.data.get('total_chunks', 1))
            file_name = request.data.get('file_name', 'upload')
            chunk_data = request.FILES.get('chunk')
            upload_id = request.data.get('upload_id')  # Unique identifier for this upload
            
            if not chunk_data or not upload_id:
                return Response(
                    {'error': 'Missing chunk data or upload_id'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Create temporary directory for chunks
            temp_dir = os.path.join(tempfile.gettempdir(), 'chunked_uploads', upload_id)
            os.makedirs(temp_dir, exist_ok=True)
            
            # Save chunk to temporary file
            chunk_path = os.path.join(temp_dir, f'chunk_{chunk_number:04d}')
            with open(chunk_path, 'wb') as chunk_file:
                for chunk in chunk_data.chunks():
                    chunk_file.write(chunk)
            
            # Check if all chunks are received
            if chunk_number + 1 == total_chunks:
                # Reassemble file from chunks
                final_file_path = os.path.join(temp_dir, 'final_file')
                
                with open(final_file_path, 'wb') as final_file:
                    for i in range(total_chunks):
                        chunk_file_path = os.path.join(temp_dir, f'chunk_{i:04d}')
                        if os.path.exists(chunk_file_path):
                            with open(chunk_file_path, 'rb') as chunk_file:
                                final_file.write(chunk_file.read())
                            # Clean up chunk file
                            os.remove(chunk_file_path)
                
                # Validate the reassembled file
                try:
                    with open(final_file_path, 'rb') as f:
                        file_content = ContentFile(f.read(), name=file_name)
                        
                    # Apply security validation
                    from .validators import validate_file_security
                    validate_file_security(file_content)
                    
                    # Save to proper storage
                    file_path = default_storage.save(f'chunked_uploads/{file_name}', file_content)
                    file_url = default_storage.url(file_path)
                    
                    # Clean up temporary directory
                    os.remove(final_file_path)
                    os.rmdir(temp_dir)
                    
                    return Response({
                        'status': 'complete',
                        'file_path': file_path,
                        'file_url': file_url,
                        'message': 'File uploaded successfully'
                    }, status=status.HTTP_201_CREATED)
                    
                except Exception as e:
                    # Clean up on validation failure
                    if os.path.exists(final_file_path):
                        os.remove(final_file_path)
                    if os.path.exists(temp_dir):
                        import shutil
                        shutil.rmtree(temp_dir)
                    
                    return Response({
                        'error': f'File validation failed: {str(e)}'
                    }, status=status.HTTP_400_BAD_REQUEST)
            
            else:
                # Return progress for partial upload
                return Response({
                    'status': 'chunk_received',
                    'chunk_number': chunk_number,
                    'total_chunks': total_chunks,
                    'progress': ((chunk_number + 1) / total_chunks) * 100
                }, status=status.HTTP_200_OK)
                
        except Exception as e:
            return Response({
                'error': f'Upload failed: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
