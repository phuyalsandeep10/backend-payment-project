from rest_framework_nested import routers
from .views import ClientViewSet
from apps.deals.views import DealViewSet, PaymentViewSet, ActivityLogViewSet

router = routers.SimpleRouter()
router.register(r'', ClientViewSet, basename='client')

clients_router = routers.NestedSimpleRouter(router, r'', lookup='client')
clients_router.register(r'deals', DealViewSet, basename='client-deals')

# Third level nesting: clients/{id}/deals/{id}/payments/
deals_router = routers.NestedSimpleRouter(clients_router, r'deals', lookup='deal')
deals_router.register(r'payments', PaymentViewSet, basename='client-deal-payments')
deals_router.register(r'activity', ActivityLogViewSet, basename='client-deal-activity')

urlpatterns = router.urls + clients_router.urls + deals_router.urls
