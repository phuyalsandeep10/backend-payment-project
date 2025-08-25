"""
Atomic Financial Operations Views
API endpoints that use atomic operations for thread-safe financial operations
"""

from rest_framework import status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from django.core.exceptions import ValidationError
from django.utils import timezone
from decimal import Decimal
from .atomic_operations import AtomicFinancialOperations
from .models import Deal, Payment
from commission.models import Commission
from permissions.permissions import IsOrgAdminOrSuperAdmin
import logging

logger = logging.getLogger('atomic_views')

class AtomicDealOperationsView(APIView):
    """
    API endpoints for atomic deal operations
    """
    permission_classes = [IsOrgAdminOrSuperAdmin]
    
    def post(self, request, deal_id):
        """
        Perform atomic deal operations
        """
        operation = request.data.get('operation')
        
        try:
            if operation == 'status_change':
                result = AtomicFinancialOperations.atomic_deal_status_change(
                    deal_id=deal_id,
                    new_verification_status=request.data.get('verification_status'),
                    new_payment_status=request.data.get('payment_status'),
                    user=request.user
                )
                
            elif operation == 'verification_workflow':
                result = AtomicFinancialOperations.atomic_deal_verification_workflow(
                    deal_id=deal_id,
                    verification_decision=request.data.get('verification_decision'),
                    verification_notes=request.data.get('verification_notes', ''),
                    user=request.user
                )
                
            elif operation == 'create_payment':
                result = AtomicFinancialOperations.atomic_payment_creation(
                    deal_id=deal_id,
                    payment_data=request.data.get('payment_data', {}),
                    user=request.user
                )
                
            else:
                return Response(
                    {'error': f'Unknown operation: {operation}'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            return Response(result, status=status.HTTP_200_OK)
            
        except ValidationError as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f"Atomic deal operation failed: {str(e)}")
            return Response(
                {'error': 'Internal server error'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class AtomicBulkOperationsView(APIView):
    """
    API endpoints for atomic bulk operations
    """
    permission_classes = [IsOrgAdminOrSuperAdmin]
    
    def post(self, request):
        """
        Perform atomic bulk operations
        """
        operation = request.data.get('operation')
        
        try:
            if operation == 'bulk_deal_status_update':
                result = AtomicFinancialOperations.atomic_bulk_deal_status_update(
                    deal_ids=request.data.get('deal_ids', []),
                    status_updates=request.data.get('status_updates', {}),
                    user=request.user
                )
                
            else:
                return Response(
                    {'error': f'Unknown bulk operation: {operation}'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            return Response(result, status=status.HTTP_200_OK)
            
        except ValidationError as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f"Atomic bulk operation failed: {str(e)}")
            return Response(
                {'error': 'Internal server error'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class AtomicCommissionOperationsView(APIView):
    """
    API endpoints for atomic commission operations
    """
    permission_classes = [IsOrgAdminOrSuperAdmin]
    
    def post(self, request, commission_id):
        """
        Perform atomic commission operations
        """
        operation = request.data.get('operation')
        
        try:
            if operation == 'recalculate':
                result = AtomicFinancialOperations.atomic_commission_calculation(
                    commission_id=commission_id,
                    recalculate_sales=request.data.get('recalculate_sales', True),
                    user=request.user
                )
                
            else:
                return Response(
                    {'error': f'Unknown commission operation: {operation}'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            return Response(result, status=status.HTTP_200_OK)
            
        except ValidationError as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f"Atomic commission operation failed: {str(e)}")
            return Response(
                {'error': 'Internal server error'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class OptimisticLockingView(APIView):
    """
    API endpoints for optimistic locking operations
    """
    permission_classes = [IsOrgAdminOrSuperAdmin]
    
    def post(self, request):
        """
        Save model with optimistic locking
        """
        model_type = request.data.get('model_type')
        model_id = request.data.get('model_id')
        update_data = request.data.get('update_data', {})
        
        try:
            if model_type == 'deal':
                deal = Deal.objects.get(id=model_id)
                
                # Update fields
                for field, value in update_data.items():
                    if hasattr(deal, field) and field not in ['id', 'created_at', 'lock_version']:
                        setattr(deal, field, value)
                
                # Save with optimistic locking
                deal.save_with_optimistic_lock()
                
                result = {
                    'model_type': 'deal',
                    'model_id': str(deal.id),
                    'lock_version': deal.lock_version,
                    'updated_at': deal.updated_at.isoformat()
                }
                
            elif model_type == 'commission':
                commission = Commission.objects.get(id=model_id)
                
                # Update fields
                for field, value in update_data.items():
                    if hasattr(commission, field) and field not in ['id', 'created_at', 'lock_version']:
                        setattr(commission, field, value)
                
                # Save with optimistic locking
                commission.save_with_optimistic_lock()
                
                result = {
                    'model_type': 'commission',
                    'model_id': commission.id,
                    'lock_version': commission.lock_version,
                    'updated_at': commission.updated_at.isoformat()
                }
                
            else:
                return Response(
                    {'error': f'Unsupported model type: {model_type}'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            return Response(result, status=status.HTTP_200_OK)
            
        except ValidationError as e:
            if "modified by another user" in str(e):
                return Response(
                    {
                        'error': 'optimistic_lock_failure',
                        'message': str(e)
                    },
                    status=status.HTTP_409_CONFLICT
                )
            else:
                return Response(
                    {'error': str(e)},
                    status=status.HTTP_400_BAD_REQUEST
                )
        except Exception as e:
            logger.error(f"Optimistic locking operation failed: {str(e)}")
            return Response(
                {'error': 'Internal server error'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def get(self, request):
        """
        Check for concurrent modifications
        """
        model_type = request.query_params.get('model_type')
        model_id = request.query_params.get('model_id')
        
        try:
            if model_type == 'deal':
                deal = Deal.objects.get(id=model_id)
                concurrent_modification = deal.refresh_with_lock_check()
                
                result = {
                    'model_type': 'deal',
                    'model_id': str(deal.id),
                    'lock_version': deal.lock_version,
                    'concurrent_modification': concurrent_modification,
                    'last_updated': deal.updated_at.isoformat()
                }
                
            elif model_type == 'commission':
                commission = Commission.objects.get(id=model_id)
                concurrent_modification = commission.refresh_with_lock_check()
                
                result = {
                    'model_type': 'commission',
                    'model_id': commission.id,
                    'lock_version': commission.lock_version,
                    'concurrent_modification': concurrent_modification,
                    'last_updated': commission.updated_at.isoformat()
                }
                
            else:
                return Response(
                    {'error': f'Unsupported model type: {model_type}'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            return Response(result, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Lock check failed: {str(e)}")
            return Response(
                {'error': 'Internal server error'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )