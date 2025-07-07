from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from deals.models import Deal,Payment,PaymentInvoice
from .serializers import (PaymentStatusSerializer,VerifierInvoiceSerializer,
                          PaymentFailureReasonSerializer,PaymentMethodSerializer,
                          Refund_or_BadDebtSerializer,InvoiceStatusSerializer,AuditLogSerializer)
from .models import AuditLogs
from .permissions import HasVerifierPermission, IsVerifier
from django.db.models import Sum, Avg, Count, Q
from rest_framework import generics , status
from .serializers import VerifierDealSerializer
from rest_framework import viewsets
from deals.serializers import PaymentApprovalSerializer,PaymentInvoiceSerializer,DealSerializer, PaymentSerializer
from deals.models import PaymentApproval
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
import json
from django.utils import timezone
from datetime import timedelta
from django.db.models.functions import TruncDay, TruncWeek, TruncMonth
import logging
from rest_framework.pagination import PageNumberPagination

logger = logging.getLogger(__name__)

def get_verifier_chart_data(organization, period):
    """
    Generate data for verifier dashboard charts based on the selected period.
    """
    now = timezone.now()
    if period == 'daily':
        # Last 7 days
        start_date = (now - timedelta(days=6)).date()
        trunc_period = TruncDay
        date_format = "%Y-%m-%d"
    elif period == 'weekly':
        # Last 4 weeks
        start_date = (now - timedelta(weeks=4)).date()
        trunc_period = TruncWeek
        date_format = "W%U, %Y"
    else:  # monthly is default
        # Last 12 months
        start_date = (now - timedelta(days=365)).date()
        trunc_period = TruncMonth
        date_format = "%b %Y"
    
    end_date = now.date()

    verified_invoices_trend = PaymentInvoice.objects.filter(
        deal__organization=organization,
        invoice_status='verified',
        invoice_date__gte=start_date,
        invoice_date__lte=end_date
    ).annotate(
        period_start=trunc_period('invoice_date')
    ).values('period_start').annotate(
        total_verified_amount=Sum('payment__received_amount'),
        count_verified=Count('id')
    ).order_by('period_start')

    verification_trend_data = [
        {
            'label': item['period_start'].strftime(date_format),
            'total_amount': item['total_verified_amount'] or 0,
            'count': item['count_verified']
        }
        for item in verified_invoices_trend
    ]
    
    return {
        'verification_trend': verification_trend_data,
    }


@swagger_auto_schema(
    method='get',
    operation_description="Get comprehensive payment verification statistics and dashboard data",
    responses={
        200: PaymentStatusSerializer,
        400: "Bad Request - User must belong to an organization",
        401: "Unauthorized",
        403: "Forbidden - Insufficient permissions"
    },
    manual_parameters=[
        openapi.Parameter(
            'Authorization',
            openapi.IN_HEADER,
            description="Token authentication header (format: 'Token <your_token>')",
            type=openapi.TYPE_STRING,
            required=True
        )
    ],
    tags=['Verifier Dashboard']
)
@api_view(['GET'])
@permission_classes([HasVerifierPermission])
def payment_stats(request):
    try:
        # Get the current user
        user = request.user
        period = request.GET.get('period', 'monthly')

        # Ensure user has organization
        if not user.organization:
            logger.warning(f"Unauthorized access attempt to verifier dashboard by user {user.id} without organization.")
            return Response(
                {'error': 'User must belong to an organization'}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        # Filter payments based on the user's organization
        payments = Payment.objects.filter(deal__organization=user.organization)
        deals = Deal.objects.filter(organization=user.organization)
        payment_invoice = PaymentInvoice.objects.filter(deal__organization=user.organization)
        
        # Calculate the required statistics
        total_payments = payments.count()
        total_successful_payments = deals.filter(payment_status='full_payment').count()
        total_unsuccess_payments = deals.filter(
            payment_status__in=['initial payment', 'partial_payment']
        ).count()
        total_verification_pending_payments = payment_invoice.filter(invoice_status='pending').count()
        total_revenue = payments.aggregate(Sum('received_amount'))['received_amount__sum'] or 0
        total_refunds = payment_invoice.filter(invoice_status='refunded').count()
        total_refunded_amount = payment_invoice.filter(invoice_status='refunded').aggregate(Sum('payment__received_amount'))['payment__received_amount__sum'] or 0
       
        avg_transactional_value = payment_invoice.filter(invoice_status='verified').aggregate(avg=Avg('payment__received_amount'))['avg'] or 0
        # Get chart data
        chart_data = get_verifier_chart_data(user.organization, period)

        # Create a response dictionary
        response_data = {
            'total_payments': total_payments,
            'total_successful_payments': total_successful_payments,
            'total_unsuccess_payments': total_unsuccess_payments,
            'total_verification_pending_payments': total_verification_pending_payments,
            'total_revenue': total_revenue,
            'total_refunds': total_refunds,
            'total_refunded_amount': total_refunded_amount,
            'avg_transactional_value': avg_transactional_value,
            'chart_data': chart_data,
        }

        # Serialize the response data
        serializer = PaymentStatusSerializer(data=response_data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data)
    except Exception as e:
        logger.exception(f"Error in payment_stats view for user {request.user.id}: {e}")
        return Response(
            {'error': 'An internal server error occurred.'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )



##for page verifier invoice
@swagger_auto_schema(
    method='get',
    operation_description="Get all invoices for verification with organization filtering",
    responses={
        200: VerifierInvoiceSerializer(many=True),
        400: "Bad Request - User must belong to an organization",
        401: "Unauthorized",
        403: "Forbidden - Insufficient permissions"
    },
    tags=['Invoice Management']
)
@api_view(['GET'])
@permission_classes([HasVerifierPermission])
def verifier_invoice(request):
    try:
        # Ensure user has organization
        if not request.user.organization:
            return Response(
                {'error': 'User must belong to an organization'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        invoices = PaymentInvoice.objects.select_related('deal', 'deal__client', 'payment').filter(deal__organization=request.user.organization)
        
        # Search and Filter Logic
        search_query = request.query_params.get('search', None)
        status_filter = request.query_params.get('status', None)

        if search_query:
            invoices = invoices.filter(
                Q(deal__client__client_name__icontains=search_query) |
                Q(deal__deal_id__icontains=search_query) |
                Q(invoice_id__icontains=search_query)
            )

        if status_filter:
            invoices = invoices.filter(invoice_status__iexact=status_filter)

        data = []
        for invoice in invoices:
            data.append({
                'invoice_id': invoice.invoice_id,
                'client_name': invoice.deal.client.client_name if invoice.deal.client else 'Unknown Client',
                'deal_name': invoice.deal.deal_id,
                'invoice_date': invoice.invoice_date,
                'due_date': invoice.deal.due_date,
                'amount': invoice.payment.received_amount,
                'status': invoice.invoice_status,
                'receipt_file': invoice.payment.receipt_file.url if invoice.payment.receipt_file else None
            })

        serializer = VerifierInvoiceSerializer(data, many=True)
        return Response(serializer.data)
    except Exception as e:
        logger.exception(f"Error in verifier_invoice view for user {request.user.id}: {e}")
        return Response(
            {'error': 'An internal server error occurred.'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['DELETE'])
@permission_classes([HasVerifierPermission])
def verifier_invoice_delete(request, invoice_id):
    try:
        invoice = PaymentInvoice.objects.get(
            invoice_id=invoice_id,
            deal__organization=request.user.organization
        )
        
        invoice.delete()
        logger.info(f"User {request.user.id} deleted invoice {invoice_id} from organization {request.user.organization.id}")
        return Response({"detail": "Invoice deleted successfully."}, status=status.HTTP_204_NO_CONTENT)
    except PaymentInvoice.DoesNotExist:
        logger.warning(f"User {request.user.id} attempted to delete non-existent invoice {invoice_id}")
        return Response({"detail": "Invoice not found."}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        logger.exception(f"Error deleting invoice {invoice_id} by user {request.user.id}: {e}")
        return Response(
            {'error': 'An internal server error occurred.'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@swagger_auto_schema(
    method='get',
    operation_description="Get all pending invoices requiring verification",
    responses={
        200: VerifierInvoiceSerializer(many=True),
        401: "Unauthorized",
        403: "Forbidden - Insufficient permissions"
    },
    tags=['Invoice Management']
)
@api_view(['GET'])
@permission_classes([HasVerifierPermission])
def verifier_pending(request):
    try:
        invoices = PaymentInvoice.objects.select_related('deal', 'deal__client', 'payment').filter(
            invoice_status='pending',
            deal__organization=request.user.organization
        )
        data = []
        for invoice in invoices:
            data.append({
                'invoice_id': invoice.invoice_id,
                'client_name': invoice.deal.client.client_name if invoice.deal.client else 'Unknown Client',
                'deal_name': invoice.deal.deal_id,
                'invoice_date': invoice.invoice_date,
                'due_date': invoice.deal.due_date,
                'amount': invoice.payment.received_amount,
                'status': invoice.invoice_status,
                'receipt_file': invoice.payment.receipt_file.url if invoice.payment.receipt_file else None
            })

        serializer = VerifierInvoiceSerializer(data, many=True)
        return Response(serializer.data)
    except Exception as e:
        logger.exception(f"Error in verifier_pending view for user {request.user.id}: {e}")
        return Response(
            {'error': 'An internal server error occurred.'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
    
    
@api_view(['GET'])
@permission_classes([HasVerifierPermission])
def verifier_verified(request):
    try:
        invoices = PaymentInvoice.objects.select_related('deal', 'deal__client', 'payment').filter(
            invoice_status='verified',
            deal__organization=request.user.organization
        )
        data = []
        for invoice in invoices:
            data.append({
                'invoice_id': invoice.invoice_id,
                'client_name': invoice.deal.client.client_name if invoice.deal.client else 'Unknown Client',
                'deal_name': invoice.deal.deal_id,
                'invoice_date': invoice.invoice_date,
                'due_date': invoice.deal.due_date,
                'amount': invoice.payment.received_amount,
                'status': invoice.invoice_status,
                'receipt_file': invoice.payment.receipt_file.url if invoice.payment.receipt_file else None
            })

        serializer = VerifierInvoiceSerializer(data, many=True)
        return Response(serializer.data)
    except Exception as e:
        logger.exception(f"Error in verifier_verified view for user {request.user.id}: {e}")
        return Response(
            {'error': 'An internal server error occurred.'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([HasVerifierPermission])
def verifier_rejected(request):
    try:
        invoices = PaymentInvoice.objects.select_related('deal', 'deal__client', 'payment').filter(
            invoice_status='rejected',
            deal__organization=request.user.organization
        )
        data = []
        for invoice in invoices:
            data.append({
                'invoice_id': invoice.invoice_id,
                'client_name': invoice.deal.client.client_name if invoice.deal.client else 'Unknown Client',
                'deal_name': invoice.deal.deal_id,
                'invoice_date': invoice.invoice_date,
                'due_date': invoice.deal.due_date,
                'amount': invoice.payment.received_amount,
                'status': invoice.invoice_status,
                'receipt_file': invoice.payment.receipt_file.url if invoice.payment.receipt_file else None
            })

        serializer = VerifierInvoiceSerializer(data, many=True)
        return Response(serializer.data)
    except Exception as e:
        logger.exception(f"Error in verifier_rejected view for user {request.user.id}: {e}")
        return Response(
            {'error': 'An internal server error occurred.'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


class VerifierDealViewSet(viewsets.ModelViewSet):
    serializer_class = VerifierDealSerializer
    permission_classes = [HasVerifierPermission]
    
    def get_queryset(self):
        # For swagger schema generation, return empty queryset
        if getattr(self, 'swagger_fake_view', False):
            return Deal.objects.none()
            
        if not self.request.user.organization:
            return Deal.objects.none()
            
        return Deal.objects.filter(organization=self.request.user.organization)
    
    
class PaymentApprovalViewSet(viewsets.ModelViewSet):
    serializer_class = PaymentApprovalSerializer
    permission_classes = [HasVerifierPermission]
    
    def get_queryset(self):
        # For swagger schema generation, return empty queryset
        if getattr(self, 'swagger_fake_view', False):
            return PaymentApproval.objects.none()
            
        if not self.request.user.organization:
            return PaymentApproval.objects.none()
            
        return PaymentApproval.objects.filter(deal__organization=self.request.user.organization)

    def perform_create(self, serializer):
        serializer.save(approved_by=self.request.user)
        
        
        
        
@api_view(['GET'])
@permission_classes([HasVerifierPermission])
def payment_failure_reasons(request):
    try:
        if not request.user.organization:
            return Response(
                {'error': 'User must belong to an organization'}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        payments = PaymentApproval.objects.filter(deal__organization=request.user.organization)
        
        insufficient_funds = payments.filter(failure_remarks = 'insufficient_funds').count()
        invalid_card = payments.filter(failure_remarks = 'invalid_card').count()
        bank_decline = payments.filter(failure_remarks = 'bank_decline').count()
        technical_error = payments.filter(failure_remarks = 'technical_error').count()
        cheque_bounce = payments.filter(failure_remarks = 'cheque_bounce').count()
        payment_received_not_reflected = payments.filter(failure_remarks = 'payment_received_not_reflected').count()
        
        data = {
            'insufficient_funds': insufficient_funds,
            'invalid_card': invalid_card,
            'bank_decline': bank_decline,
            'technical_error': technical_error,
            'cheque_bounce': cheque_bounce,
            'payment_received_not_reflected': payment_received_not_reflected
        }

        return Response(data, status=status.HTTP_200_OK)
    except Exception as e:
        logger.exception(f"Error in payment_failure_reasons view for user {request.user.id}: {e}")
        return Response(
            {'error': 'An internal server error occurred.'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
    
    
@api_view(['GET'])
@permission_classes([HasVerifierPermission])
def payment_methods(request):
    try:
        if not request.user.organization:
            return Response(
                {'error': 'User must belong to an organization'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        deals = Deal.objects.filter(organization=request.user.organization)
        credit_card = deals.filter(payment_method='credit_card').count()
        bank_transfer = deals.filter(payment_method='bank_transfer').count()
        mobile_wallet = deals.filter(payment_method='mobile_wallet').count()
        cheque = deals.filter(payment_method='cheque').count()
        qr_payment = deals.filter(payment_method='qr_payment').count()
        
        data = {
            'credit_card': credit_card,
            'bank_transfer': bank_transfer,
            'mobile_wallet': mobile_wallet,
            'cheque': cheque,
            'qr_payment': qr_payment
        }
        
        serializer = PaymentMethodSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except Exception as e:
        logger.exception(f"Error in payment_methods view for user {request.user.id}: {e}")
        return Response(
            {'error': 'An internal server error occurred.'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )



@api_view(['GET'])
@permission_classes([HasVerifierPermission])
def refunded_invoice(request):
    try:
        if not request.user.organization:
            return Response(
                {'error': 'User must belong to an organization'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        refunds = PaymentInvoice.objects.select_related('deal', 'deal__client', 'payment').filter(deal__organization=request.user.organization, invoice_status='refunded')
        
        data = []
        for refund in refunds:
            data.append({
                'invoice_id': refund.invoice_id,
                'client': refund.deal.client.client_name if refund.deal.client else 'Unknown Client',
                'amount': refund.payment.received_amount,
                'status': 'refunded',
                'reasons': refund.invoice_status,
                'date': refund.invoice_date
            })
        serializer = Refund_or_BadDebtSerializer(data, many=True)
        return Response(data, status=status.HTTP_200_OK)
    except Exception as e:
        logger.exception(f"Error in refunded_invoice view for user {request.user.id}: {e}")
        return Response(
            {'error': 'An internal server error occurred.'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )



@api_view(['GET'])
@permission_classes([HasVerifierPermission])
def bad_debt_invoice(request):
    try:
        if not request.user.organization:
            return Response(
                {'error': 'User must belong to an organization'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        bad_debts = PaymentInvoice.objects.select_related('deal', 'deal__client', 'payment').filter(deal__organization=request.user.organization, invoice_status='bad_debt')
        
        data = []
        for bad_debt in bad_debts:
            data.append({
                'invoice_id': bad_debt.invoice_id,
                'client': bad_debt.deal.client.client_name if bad_debt.deal.client else 'Unknown Client',
                'amount': bad_debt.payment.received_amount,
                'status': 'bad_debt',
                'reasons': bad_debt.invoice_status,
                'date': bad_debt.invoice_date
            })
        serializer = Refund_or_BadDebtSerializer(data, many=True)
        return Response(data, status=status.HTTP_200_OK)
    except Exception as e:
        logger.exception(f"Error in bad_debt_invoice view for user {request.user.id}: {e}")
        return Response(
            {'error': 'An internal server error occurred.'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([HasVerifierPermission])
def recent_refund_or_bad_debt(request):
    """
    Endpoint to get recent refunds or bad debts.
    """
    try:
        if not request.user.organization:
            return Response(
                {'error': 'User must belong to an organization'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        recent_refunds = PaymentInvoice.objects.filter(
            deal__organization=request.user.organization,
            invoice_status__in=['refunded', 'bad_debt']
        ).order_by('-invoice_date')[:5]  # Get the 5 most recent refunds or bad debts
        
        serializer = PaymentInvoiceSerializer(recent_refunds, many=True)
        return Response(serializer.data)
    except Exception as e:
        logger.exception(f"Error in recent_refund_or_bad_debt view for user {request.user.id}: {e}")
        return Response(
            {'error': 'An internal server error occurred.'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
    
@api_view(['GET'])
@permission_classes([HasVerifierPermission])
def verification_queue(request):
    """
    Endpoint to get the verification queue.
    """
    try:
        if not request.user.organization:
            return Response(
                {'error': 'User must belong to an organization'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        pending_invoices = PaymentInvoice.objects.filter(
            deal__organization=request.user.organization,
            invoice_status='pending'
        ).order_by('-invoice_date')[:5]
        serialized_data = PaymentInvoiceSerializer(pending_invoices, many=True).data
        return Response(serialized_data)
    except Exception as e:
        logger.exception(f"Error in verification_queue view for user {request.user.id}: {e}")
        return Response(
            {'error': 'An internal server error occurred.'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
    
    
@api_view(['GET'])
@permission_classes([HasVerifierPermission])
def invoice_status_overview(request):
    """
    Endpoint to get an overview of invoice statuses.
    """
    try:
        if not request.user.organization:
            return Response(
                {'error': 'User must belong to an organization'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        invoices = PaymentInvoice.objects.filter(deal__organization=request.user.organization)
        
        paid_invoices = invoices.filter(invoice_status='verified').count()
        pending_invoices = invoices.filter(invoice_status='pending').count()
        rejected_invoices = invoices.filter(invoice_status='rejected').count() 
        refunded_invoices = invoices.filter(invoice_status='refunded').count()
        bad_debt_invoices = invoices.filter(invoice_status='bad_debt').count()
        data = {
            'paid_invoices': paid_invoices,
            'pending_invoices': pending_invoices,
            'rejected_invoices': rejected_invoices,
            'refunded_invoices': refunded_invoices,
            'bad_debt_invoices': bad_debt_invoices
        }
        serializer = InvoiceStatusSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except Exception as e:
        logger.exception(f"Error in invoice_status_overview view for user {request.user.id}: {e}")
        return Response(
            {'error': 'An internal server error occurred.'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )




@api_view(['GET'])
@permission_classes([HasVerifierPermission])
def payment_status_distribution(request):
    """
    Endpoint to get an overview of invoice statuses.
    """
    try:
        if not request.user.organization:
            return Response(
                {'error': 'User must belong to an organization'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        invoices = PaymentInvoice.objects.filter(deal__organization=request.user.organization)
        invoices_count = invoices.count()
        
        paid_invoices = (invoices.filter(invoice_status='verified').count()/invoices_count) * 100 if invoices_count else 0
        pending_invoices = (invoices.filter(invoice_status='pending').count()/invoices_count) * 100 if invoices_count else 0
        rejected_invoices = (invoices.filter(invoice_status='rejected').count()/invoices_count) * 100 if invoices_count else 0
        refunded_invoices = (invoices.filter(invoice_status='refunded').count()/invoices_count) * 100 if invoices_count else 0
        bad_debt_invoices = (invoices.filter(invoice_status='bad_debt').count()/invoices_count) * 100 if invoices_count else 0  
        
        data = {
            'paid_invoices': paid_invoices,
            'pending_invoices': pending_invoices,
            'rejected_invoices': rejected_invoices,
            'refunded_invoices': refunded_invoices,
            'bad_debt_invoices': bad_debt_invoices
        }
        serializer = InvoiceStatusSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except Exception as e:
        logger.exception(f"Error in payment_status_distribution view for user {request.user.id}: {e}")
        return Response(
            {'error': 'An internal server error occurred.'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
    
@swagger_auto_schema(
    method='get',
    operation_description="Retrieve audit logs with pagination.",
    manual_parameters=[
        openapi.Parameter('page', openapi.IN_QUERY, description="Page number", type=openapi.TYPE_INTEGER),
        openapi.Parameter('page_size', openapi.IN_QUERY, description="Number of results per page", type=openapi.TYPE_INTEGER),
    ],
    responses={
        200: AuditLogSerializer(many=True),
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden"
    },
    tags=['Audit Logs']
)
@api_view(['GET'])
@permission_classes([HasVerifierPermission])
def audit_logs(request):
    """
    Retrieve audit logs for the user's organization with pagination.
    Supports filtering by user, action, and a date range.
    """
    try:
        organization = request.user.organization
        if not organization:
            return Response(
                {'error': 'User must belong to an organization'},
                status=status.HTTP_400_BAD_REQUEST
            )

        queryset = AuditLogs.objects.filter(organization=organization).order_by('-timestamp')
        
        # Pagination
        paginator = PageNumberPagination()
        paginator.page_size = 10  # Default page size
        paginated_queryset = paginator.paginate_queryset(queryset, request)
        
        serializer = AuditLogSerializer(paginated_queryset, many=True)
        return paginator.get_paginated_response(serializer.data)
    
    except Exception as e:
        logger.exception(f"Error retrieving audit logs for organization {request.user.organization.id if request.user.organization else 'N/A'}: {e}")
        return Response(
            {'error': 'An internal server error occurred.'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )




@swagger_auto_schema(
    method='get',
    operation_description="Get payment details for verification form",
    responses={
        200: openapi.Response(
            description="Payment and deal details",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'deal': openapi.Schema(type=openapi.TYPE_OBJECT),
                    'payment': openapi.Schema(type=openapi.TYPE_OBJECT),
                }
            )
        ),
        404: "Payment not found",
        401: "Unauthorized",
        403: "Forbidden - Insufficient permissions"
    },
    tags=['Payment Verification']
)
@swagger_auto_schema(
    method='post',
    operation_description="Submit payment verification decision",
    request_body=PaymentApprovalSerializer,
    responses={
        200: openapi.Response(
            description="Verification successful",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'message': openapi.Schema(type=openapi.TYPE_STRING)
                }
            )
        ),
        400: "Bad Request - Invalid data",
        404: "Payment not found",
        401: "Unauthorized",
        403: "Forbidden - Insufficient permissions"
    },
    tags=['Payment Verification']
)
@api_view(['GET', 'POST'])
@permission_classes([HasVerifierPermission])
def payment_verifier_form(request, payment_id):
    try:
        # Retrieve the payment and its associated invoice
        payment = Payment.objects.get(id=payment_id)
        invoice = PaymentInvoice.objects.get(payment=payment)

        # Check if the user has permission to verify this payment
        # (You might want to add more specific object-level permission checks)
        if not request.user.has_perm('deals.verify_payments'):
            return Response({'status': 'error', 'message': 'Permission denied.'}, status=status.HTTP_403_FORBIDDEN)

        # Update the invoice status based on the approval_status
        approval_status = request.data.get('approval_status')
        if approval_status == 'approved':
            invoice.invoice_status = 'verified'
        elif approval_status == 'rejected':
            invoice.invoice_status = 'rejected'
        elif approval_status == 'bad_debt':
            invoice.invoice_status = 'bad_debt'
        
        # Save the invoice
        invoice.save()

        # Log the audit trail directly
        AuditLogs.objects.create(
            user=request.user,
            action=f"Invoice status changed to {invoice.invoice_status}",
            details=f"Invoice {invoice.invoice_id} status was changed to {invoice.invoice_status} by {request.user.username}",
            organization=request.user.organization
        )

        # Create the PaymentApproval entry
        remarks = request.data.get('remarks')
        approval_data = {
            'payment': invoice.payment,
            'approved_by': request.user,
            'amount_in_invoice': invoice.payment.received_amount,
            'approved_remarks': remarks
        }

        approval = PaymentApproval(**approval_data)
        approval.save()

        # Return a success response
        return Response({
            'status': 'success',
            'message': 'Invoice status successfully updated.',
            'level': 'success',
        }, status=status.HTTP_200_OK)

    except Payment.DoesNotExist:
        return Response({'status': 'error', 'message': 'Payment not found.'}, status=status.HTTP_404_NOT_FOUND)
    except PaymentInvoice.DoesNotExist:
        return Response({'status': 'error', 'message': 'Invoice not found for the given payment.'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        # Log the exception for debugging
        return Response({'status': 'error', 'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)