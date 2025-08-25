"""
Service Shortcuts - Task 2.1.2, 2.1.3

Convenient access to business logic services.
"""

from .service_registry import get_service

# Business logic services
def get_deal_service(user=None, organization=None):
    """Get DealService instance"""
    return get_service('deal_service', user=user, organization=organization)

def get_payment_service(user=None, organization=None):
    """Get PaymentService instance"""  
    return get_service('payment_service', user=user, organization=organization)

# Pre-configured instances for common usage
deal_service = get_service('deal_service')
payment_service = get_service('payment_service')

__all__ = [
    'get_deal_service',
    'get_payment_service', 
    'deal_service',
    'payment_service'
]

