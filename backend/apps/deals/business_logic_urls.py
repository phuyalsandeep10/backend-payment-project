"""
URL configuration for business logic optimization endpoints
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .business_logic_views import BusinessLogicOptimizationViewSet

# Create router for business logic optimization
router = DefaultRouter()
router.register(r'business-logic', BusinessLogicOptimizationViewSet, basename='business-logic')

urlpatterns = [
    path('api/optimization/', include(router.urls)),
]

# Additional URL patterns for specific optimization endpoints
optimization_patterns = [
    # Deal workflow optimization
    path('api/optimization/deals/workflows/optimize/', 
         BusinessLogicOptimizationViewSet.as_view({'post': 'optimize_deal_workflows'}),
         name='optimize-deal-workflows'),
    
    path('api/optimization/deals/workflows/metrics/', 
         BusinessLogicOptimizationViewSet.as_view({'get': 'get_deal_workflow_metrics'}),
         name='deal-workflow-metrics'),
    
    # User management optimization
    path('api/optimization/users/management/optimize/', 
         BusinessLogicOptimizationViewSet.as_view({'post': 'optimize_user_management'}),
         name='optimize-user-management'),
    
    path('api/optimization/users/activity/analytics/', 
         BusinessLogicOptimizationViewSet.as_view({'get': 'get_user_activity_analytics'}),
         name='user-activity-analytics'),
    
    path('api/optimization/users/bulk-operations/', 
         BusinessLogicOptimizationViewSet.as_view({'post': 'execute_bulk_user_operations'}),
         name='bulk-user-operations'),
    
    path('api/optimization/users/search/', 
         BusinessLogicOptimizationViewSet.as_view({'get': 'efficient_user_search'}),
         name='efficient-user-search'),
    
    # Dashboard and reporting
    path('api/optimization/dashboard/', 
         BusinessLogicOptimizationViewSet.as_view({'get': 'get_business_logic_dashboard'}),
         name='business-logic-dashboard'),
    
    path('api/optimization/reports/generate/', 
         BusinessLogicOptimizationViewSet.as_view({'post': 'generate_optimization_report'}),
         name='generate-optimization-report'),
]

urlpatterns.extend(optimization_patterns)