# Development Guide - Backend_PRS

## Overview

This guide provides comprehensive instructions for developers working on the Backend_PRS Payment Receiving System. It covers development setup, coding standards, testing practices, and contribution guidelines.

## Table of Contents

1. [Development Environment Setup](#development-environment-setup)
2. [Project Structure](#project-structure)
3. [Coding Standards](#coding-standards)
4. [API Development](#api-development)
5. [Database Development](#database-development)
6. [Testing](#testing)
7. [Debugging](#debugging)
8. [Performance Optimization](#performance-optimization)
9. [Security Guidelines](#security-guidelines)
10. [Contribution Guidelines](#contribution-guidelines)
11. [Tools and Utilities](#tools-and-utilities)

## Development Environment Setup

### Prerequisites

- Python 3.8+ (recommended: 3.11)
- PostgreSQL 12+
- Redis 6+
- Git
- Code editor (VS Code, PyCharm, etc.)

### Local Development Setup

```bash
# Clone the repository
git clone https://github.com/your-username/Backend_PRS.git
cd Backend_PRS

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Set up environment variables
cp .env.example .env
# Edit .env with your local settings

# Setup database
python manage.py migrate
python manage.py setup_permissions
python manage.py seed_demo_data

# Create superuser
python manage.py createsuperuser

# Run development server
python manage.py runserver
```

### Development Dependencies

Create `requirements-dev.txt`:

```txt
# Development tools
black==23.12.1
flake8==6.1.0
isort==5.13.2
mypy==1.8.0
pre-commit==3.6.0

# Testing
pytest==7.4.3
pytest-django==4.7.0
pytest-cov==4.1.0
factory-boy==3.3.1
faker==21.0.0

# Debugging
django-debug-toolbar==4.2.0
django-extensions==3.2.3
ipython==8.18.1

# Documentation
sphinx==7.2.6
sphinx-rtd-theme==2.0.0
```

### IDE Configuration

#### VS Code Settings (`.vscode/settings.json`)

```json
{
  "python.defaultInterpreterPath": "./venv/bin/python",
  "python.formatting.provider": "black",
  "python.linting.enabled": true,
  "python.linting.flake8Enabled": true,
  "python.linting.mypyEnabled": true,
  "python.testing.pytestEnabled": true,
  "python.testing.unittestEnabled": false,
  "python.testing.pytestArgs": [
    "tests"
  ],
  "files.exclude": {
    "**/__pycache__": true,
    "**/*.pyc": true,
    "**/venv": true,
    "**/.pytest_cache": true
  }
}
```

#### PyCharm Configuration

1. Set Python interpreter to virtual environment
2. Configure code style to use Black
3. Enable Django support
4. Set up run configurations for manage.py commands

## Project Structure

```
Backend_PRS/
├── backend/                    # Django project root
│   ├── core_config/           # Project configuration
│   │   ├── __init__.py
│   │   ├── settings.py        # Django settings
│   │   ├── urls.py           # URL configuration
│   │   ├── wsgi.py           # WSGI configuration
│   │   ├── asgi.py           # ASGI configuration
│   │   └── middleware.py     # Custom middleware
│   ├── authentication/       # User authentication
│   ├── organization/         # Organization management
│   ├── permissions/          # Role-based permissions
│   ├── clients/             # Client management
│   ├── deals/               # Deal management (core)
│   ├── commission/          # Commission tracking
│   ├── team/                # Team management
│   ├── project/             # Project management
│   ├── notifications/       # Notification system
│   ├── Sales_dashboard/     # Sales analytics
│   ├── Verifier_dashboard/  # Verification workflows
│   ├── static/              # Static files
│   ├── media/               # Media files
│   ├── logs/                # Application logs
│   └── manage.py            # Django management
├── scripts/                 # Deployment scripts
├── tests/                   # Test files
├── documentation/           # Documentation
├── requirements.txt         # Production dependencies
├── requirements-dev.txt     # Development dependencies
├── .env.example            # Environment variables template
├── .gitignore              # Git ignore rules
├── README.md               # Project documentation
└── render.yaml             # Render deployment config
```

### Django App Structure

Each Django app follows this structure:

```
app_name/
├── __init__.py
├── admin.py              # Admin interface
├── apps.py               # App configuration
├── models.py             # Data models
├── views.py              # API views
├── serializers.py        # DRF serializers
├── urls.py               # URL routing
├── permissions.py        # Custom permissions
├── utils.py              # Utility functions
├── signals.py            # Django signals
├── tests.py              # Unit tests
├── migrations/           # Database migrations
└── management/           # Custom management commands
    └── commands/
```

## Coding Standards

### Python Code Style

We follow PEP 8 with some modifications:

```python
# Good example
class DealViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing deals with proper permissions and filtering.
    """
    serializer_class = DealSerializer
    permission_classes = [IsAuthenticated, HasDealPermission]
    filter_backends = [DjangoFilterBackend, SearchFilter]
    filterset_fields = ['status', 'payment_method']
    search_fields = ['deal_id', 'client__name']
    
    def get_queryset(self):
        """Filter deals based on user permissions."""
        user = self.request.user
        if user.is_superuser:
            return Deal.objects.all()
        return Deal.objects.filter(organization=user.organization)
    
    def perform_create(self, serializer):
        """Auto-assign organization and creator."""
        serializer.save(
            organization=self.request.user.organization,
            created_by=self.request.user
        )
```

### Django Model Guidelines

```python
class Deal(models.Model):
    """
    Model representing a business deal with payments.
    
    Attributes:
        id: UUID primary key for security
        deal_id: Auto-generated human-readable ID
        client: Foreign key to client
        amount: Deal amount with validation
        status: Deal status with choices
        organization: Multi-tenant organization
        created_by: Deal creator
        created_at: Auto timestamp
        updated_at: Auto timestamp
    """
    
    class Status(models.TextChoices):
        PENDING = 'pending', 'Pending'
        APPROVED = 'approved', 'Approved'
        COMPLETED = 'completed', 'Completed'
        CANCELLED = 'cancelled', 'Cancelled'
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    deal_id = models.CharField(max_length=20, unique=True, editable=False)
    client = models.ForeignKey(
        'clients.Client',
        on_delete=models.CASCADE,
        related_name='deals'
    )
    amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        validators=[MinValueValidator(Decimal('0.01'))]
    )
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.PENDING
    )
    organization = models.ForeignKey(
        'organization.Organization',
        on_delete=models.CASCADE,
        related_name='deals'
    )
    created_by = models.ForeignKey(
        'authentication.User',
        on_delete=models.CASCADE,
        related_name='created_deals'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['organization', 'status']),
            models.Index(fields=['created_by', 'status']),
        ]
        permissions = [
            ('view_all_deals', 'Can view all deals'),
            ('view_own_deals', 'Can view own deals'),
        ]
    
    def __str__(self):
        return f"{self.deal_id} - {self.client.name}"
    
    def save(self, *args, **kwargs):
        """Auto-generate deal ID if not set."""
        if not self.deal_id:
            self.deal_id = self.generate_deal_id()
        super().save(*args, **kwargs)
    
    def generate_deal_id(self):
        """Generate unique deal ID."""
        last_deal = Deal.objects.order_by('-id').first()
        if last_deal:
            last_number = int(last_deal.deal_id.split('DLID')[1])
            return f"DLID{last_number + 1:04d}"
        return "DLID0001"
```

### API View Guidelines

```python
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from django.db import transaction


class DealViewSet(viewsets.ModelViewSet):
    """
    ViewSet for deal management with proper error handling.
    """
    
    @action(detail=True, methods=['post'])
    def add_payment(self, request, pk=None):
        """
        Add payment to a deal.
        
        Args:
            request: HTTP request with payment data
            pk: Deal primary key
            
        Returns:
            Response with payment data or errors
        """
        try:
            deal = self.get_object()
            serializer = PaymentSerializer(data=request.data)
            
            if serializer.is_valid():
                with transaction.atomic():
                    payment = serializer.save(
                        deal=deal,
                        created_by=request.user
                    )
                    
                    # Send notification
                    send_payment_notification(payment)
                    
                    return Response(
                        PaymentSerializer(payment).data,
                        status=status.HTTP_201_CREATED
                    )
            else:
                return Response(
                    serializer.errors,
                    status=status.HTTP_400_BAD_REQUEST
                )
                
        except Exception as e:
            logger.error(f"Error adding payment: {str(e)}")
            return Response(
                {'error': 'Failed to add payment'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
```

### Error Handling

```python
from rest_framework.views import exception_handler
from rest_framework.response import Response
import logging

logger = logging.getLogger(__name__)

def custom_exception_handler(exc, context):
    """Custom exception handler for consistent error responses."""
    response = exception_handler(exc, context)
    
    if response is not None:
        custom_response_data = {
            'success': False,
            'error': {
                'message': 'An error occurred',
                'details': response.data
            }
        }
        
        # Log the error
        logger.error(f"API Error: {exc}", exc_info=True)
        
        response.data = custom_response_data
    
    return response
```

### Pre-commit Configuration

Create `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files
      - id: check-merge-conflict

  - repo: https://github.com/psf/black
    rev: 23.12.1
    hooks:
      - id: black

  - repo: https://github.com/pycqa/isort
    rev: 5.13.2
    hooks:
      - id: isort
        args: ["--profile", "black"]

  - repo: https://github.com/pycqa/flake8
    rev: 6.1.0
    hooks:
      - id: flake8
        args: [--max-line-length=88, --extend-ignore=E203]

  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.8.0
    hooks:
      - id: mypy
        additional_dependencies: [django-stubs]
```

## API Development

### RESTful API Design

```python
# Good URL patterns
urlpatterns = [
    path('clients/', ClientViewSet.as_view({'get': 'list', 'post': 'create'})),
    path('clients/<int:pk>/', ClientViewSet.as_view({
        'get': 'retrieve',
        'put': 'update',
        'patch': 'partial_update',
        'delete': 'destroy'
    })),
    path('clients/<int:client_id>/deals/', DealViewSet.as_view({
        'get': 'list',
        'post': 'create'
    })),
]

# Use nested routes for related resources
path('deals/<uuid:deal_id>/payments/', PaymentViewSet.as_view()),
path('deals/<uuid:deal_id>/activity/', ActivityLogViewSet.as_view()),
```

### Serializer Best Practices

```python
class DealSerializer(serializers.ModelSerializer):
    """
    Serializer for Deal model with validation and computed fields.
    """
    
    client_name = serializers.CharField(source='client.name', read_only=True)
    total_paid = serializers.SerializerMethodField()
    remaining_balance = serializers.SerializerMethodField()
    
    class Meta:
        model = Deal
        fields = [
            'id', 'deal_id', 'client', 'client_name', 'amount',
            'status', 'total_paid', 'remaining_balance',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'deal_id', 'created_at', 'updated_at']
    
    def get_total_paid(self, obj):
        """Calculate total paid amount."""
        return obj.payments.filter(status='verified').aggregate(
            total=models.Sum('amount')
        )['total'] or 0
    
    def get_remaining_balance(self, obj):
        """Calculate remaining balance."""
        return obj.amount - self.get_total_paid(obj)
    
    def validate_amount(self, value):
        """Validate deal amount."""
        if value <= 0:
            raise serializers.ValidationError("Amount must be positive")
        if value > 1000000:
            raise serializers.ValidationError("Amount too large")
        return value
    
    def validate(self, attrs):
        """Cross-field validation."""
        if attrs.get('status') == 'completed':
            # Check if deal is fully paid
            if hasattr(self, 'instance') and self.instance:
                remaining = self.instance.amount - self.get_total_paid(self.instance)
                if remaining > 0:
                    raise serializers.ValidationError(
                        "Cannot complete deal with outstanding balance"
                    )
        return attrs
```

### Permission System

```python
from rest_framework.permissions import BasePermission

class HasDealPermission(BasePermission):
    """
    Custom permission class for deal operations.
    """
    
    def has_permission(self, request, view):
        """Check if user has basic deal permissions."""
        if not request.user.is_authenticated:
            return False
        
        # Super admin has all permissions
        if request.user.is_superuser:
            return True
        
        # Check role-based permissions
        if view.action == 'create':
            return request.user.has_perm('deals.add_deal')
        elif view.action in ['list', 'retrieve']:
            return request.user.has_perm('deals.view_deal')
        elif view.action in ['update', 'partial_update']:
            return request.user.has_perm('deals.change_deal')
        elif view.action == 'destroy':
            return request.user.has_perm('deals.delete_deal')
        
        return False
    
    def has_object_permission(self, request, view, obj):
        """Check if user has permission for specific object."""
        # Organization isolation
        if obj.organization != request.user.organization:
            return False
        
        # Users can only access their own deals unless they have view_all permission
        if not request.user.has_perm('deals.view_all_deals'):
            return obj.created_by == request.user
        
        return True
```

### Custom Management Commands

```python
# management/commands/seed_demo_data.py
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from faker import Faker
import random

User = get_user_model()
fake = Faker()

class Command(BaseCommand):
    help = 'Seed database with demo data'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--users',
            type=int,
            default=10,
            help='Number of users to create'
        )
        parser.add_argument(
            '--deals',
            type=int,
            default=50,
            help='Number of deals to create'
        )
    
    def handle(self, *args, **options):
        self.stdout.write("Creating demo data...")
        
        # Create users
        users_created = 0
        for _ in range(options['users']):
            user = User.objects.create_user(
                email=fake.email(),
                first_name=fake.first_name(),
                last_name=fake.last_name(),
                password='password123'
            )
            users_created += 1
        
        self.stdout.write(
            self.style.SUCCESS(f'Created {users_created} users')
        )
        
        # Create deals
        deals_created = 0
        for _ in range(options['deals']):
            # Deal creation logic here
            deals_created += 1
        
        self.stdout.write(
            self.style.SUCCESS(f'Created {deals_created} deals')
        )
```

## Database Development

### Migration Best Practices

```python
# Good migration example
from django.db import migrations, models

class Migration(migrations.Migration):
    dependencies = [
        ('deals', '0001_initial'),
    ]
    
    operations = [
        # Add field with default value
        migrations.AddField(
            model_name='deal',
            name='priority',
            field=models.CharField(
                max_length=20,
                choices=[
                    ('low', 'Low'),
                    ('medium', 'Medium'),
                    ('high', 'High'),
                ],
                default='medium'
            ),
        ),
        
        # Add index for performance
        migrations.RunSQL(
            "CREATE INDEX CONCURRENTLY idx_deals_priority ON deals_deal(priority);",
            reverse_sql="DROP INDEX IF EXISTS idx_deals_priority;"
        ),
    ]
```

### Custom QuerySets and Managers

```python
class DealQuerySet(models.QuerySet):
    """Custom QuerySet for Deal model."""
    
    def active(self):
        """Filter active deals."""
        return self.filter(status__in=['pending', 'approved'])
    
    def completed(self):
        """Filter completed deals."""
        return self.filter(status='completed')
    
    def for_organization(self, organization):
        """Filter deals for specific organization."""
        return self.filter(organization=organization)
    
    def with_payments(self):
        """Prefetch related payments."""
        return self.prefetch_related('payments')
    
    def with_totals(self):
        """Annotate with calculated totals."""
        return self.annotate(
            total_payments=models.Sum('payments__amount'),
            payment_count=models.Count('payments')
        )

class DealManager(models.Manager):
    """Custom manager for Deal model."""
    
    def get_queryset(self):
        return DealQuerySet(self.model, using=self._db)
    
    def active(self):
        return self.get_queryset().active()
    
    def completed(self):
        return self.get_queryset().completed()
```

### Database Optimization

```python
# Use select_related for foreign keys
deals = Deal.objects.select_related('client', 'organization').all()

# Use prefetch_related for reverse foreign keys
deals = Deal.objects.prefetch_related('payments').all()

# Use annotations for calculations
deals = Deal.objects.annotate(
    total_paid=models.Sum('payments__amount'),
    remaining=models.F('amount') - models.F('total_paid')
).all()

# Use bulk operations for performance
Deal.objects.bulk_create([
    Deal(client=client, amount=1000) for client in clients
])

# Use exists() instead of len() or count()
if Deal.objects.filter(client=client).exists():
    # Do something
```

## Testing

### Test Structure

```python
# tests/test_deals.py
import pytest
from django.test import TestCase
from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase
from rest_framework import status
from decimal import Decimal

from deals.models import Deal
from clients.models import Client
from organization.models import Organization

User = get_user_model()

class DealModelTest(TestCase):
    """Test Deal model functionality."""
    
    def setUp(self):
        """Set up test data."""
        self.organization = Organization.objects.create(
            name="Test Org"
        )
        self.user = User.objects.create_user(
            email="test@example.com",
            password="testpass123",
            organization=self.organization
        )
        self.client = Client.objects.create(
            name="Test Client",
            organization=self.organization,
            created_by=self.user
        )
    
    def test_deal_creation(self):
        """Test deal creation with valid data."""
        deal = Deal.objects.create(
            client=self.client,
            amount=Decimal('1000.00'),
            organization=self.organization,
            created_by=self.user
        )
        
        self.assertEqual(deal.status, 'pending')
        self.assertEqual(deal.amount, Decimal('1000.00'))
        self.assertTrue(deal.deal_id.startswith('DLID'))
    
    def test_deal_id_generation(self):
        """Test automatic deal ID generation."""
        deal1 = Deal.objects.create(
            client=self.client,
            amount=Decimal('1000.00'),
            organization=self.organization,
            created_by=self.user
        )
        deal2 = Deal.objects.create(
            client=self.client,
            amount=Decimal('2000.00'),
            organization=self.organization,
            created_by=self.user
        )
        
        self.assertEqual(deal1.deal_id, 'DLID0001')
        self.assertEqual(deal2.deal_id, 'DLID0002')

class DealAPITest(APITestCase):
    """Test Deal API endpoints."""
    
    def setUp(self):
        """Set up test data."""
        self.organization = Organization.objects.create(
            name="Test Org"
        )
        self.user = User.objects.create_user(
            email="test@example.com",
            password="testpass123",
            organization=self.organization
        )
        self.client_obj = Client.objects.create(
            name="Test Client",
            organization=self.organization,
            created_by=self.user
        )
        self.client.force_authenticate(user=self.user)
    
    def test_create_deal(self):
        """Test creating a deal via API."""
        data = {
            'client': self.client_obj.id,
            'amount': '1000.00',
            'description': 'Test deal'
        }
        
        response = self.client.post('/api/deals/deals/', data)
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Deal.objects.count(), 1)
        self.assertEqual(Deal.objects.first().amount, Decimal('1000.00'))
    
    def test_list_deals(self):
        """Test listing deals via API."""
        Deal.objects.create(
            client=self.client_obj,
            amount=Decimal('1000.00'),
            organization=self.organization,
            created_by=self.user
        )
        
        response = self.client.get('/api/deals/deals/')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 1)
    
    def test_organization_isolation(self):
        """Test that users can only see their organization's deals."""
        # Create another organization and user
        other_org = Organization.objects.create(name="Other Org")
        other_user = User.objects.create_user(
            email="other@example.com",
            password="testpass123",
            organization=other_org
        )
        
        # Create deal for other organization
        other_client = Client.objects.create(
            name="Other Client",
            organization=other_org,
            created_by=other_user
        )
        Deal.objects.create(
            client=other_client,
            amount=Decimal('2000.00'),
            organization=other_org,
            created_by=other_user
        )
        
        # Create deal for current user's organization
        Deal.objects.create(
            client=self.client_obj,
            amount=Decimal('1000.00'),
            organization=self.organization,
            created_by=self.user
        )
        
        response = self.client.get('/api/deals/deals/')
        
        # Should only see own organization's deals
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 1)
        self.assertEqual(
            response.data['results'][0]['amount'],
            '1000.00'
        )

@pytest.mark.django_db
class TestDealPermissions:
    """Test deal permissions using pytest."""
    
    def test_user_can_create_deal(self, authenticated_user, client_obj):
        """Test that authenticated user can create deals."""
        # Test implementation
        pass
    
    def test_user_cannot_access_other_org_deals(self, authenticated_user):
        """Test organization isolation."""
        # Test implementation
        pass
```

### Factory Boy for Test Data

```python
# tests/factories.py
import factory
from django.contrib.auth import get_user_model
from decimal import Decimal

from organization.models import Organization
from clients.models import Client
from deals.models import Deal

User = get_user_model()

class OrganizationFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = Organization
    
    name = factory.Sequence(lambda n: f"Organization {n}")
    email = factory.LazyAttribute(lambda obj: f"contact@{obj.name.lower().replace(' ', '')}.com")

class UserFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = User
    
    email = factory.Sequence(lambda n: f"user{n}@example.com")
    first_name = factory.Faker('first_name')
    last_name = factory.Faker('last_name')
    organization = factory.SubFactory(OrganizationFactory)
    is_active = True

class ClientFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = Client
    
    name = factory.Faker('company')
    email = factory.LazyAttribute(lambda obj: f"contact@{obj.name.lower().replace(' ', '')}.com")
    organization = factory.SubFactory(OrganizationFactory)
    created_by = factory.SubFactory(UserFactory)

class DealFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = Deal
    
    client = factory.SubFactory(ClientFactory)
    amount = factory.LazyFunction(lambda: Decimal(str(factory.Faker('random_int', min=100, max=10000).generate())))
    organization = factory.SelfAttribute('client.organization')
    created_by = factory.SelfAttribute('client.created_by')
```

### Running Tests

```bash
# Run all tests
python manage.py test

# Run specific test file
python manage.py test tests.test_deals

# Run with coverage
coverage run --source='.' manage.py test
coverage report
coverage html

# Run with pytest
pytest
pytest -v
pytest --cov=deals tests/test_deals.py
```

## Debugging

### Django Debug Toolbar

```python
# settings.py
if DEBUG:
    INSTALLED_APPS += ['debug_toolbar']
    MIDDLEWARE += ['debug_toolbar.middleware.DebugToolbarMiddleware']
    INTERNAL_IPS = ['127.0.0.1']
    
    DEBUG_TOOLBAR_CONFIG = {
        'SHOW_TEMPLATE_CONTEXT': True,
        'SHOW_TOOLBAR_CALLBACK': lambda request: DEBUG,
    }
```

### Logging Configuration

```python
# settings.py
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'file': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': BASE_DIR / 'logs' / 'debug.log',
            'formatter': 'verbose',
        },
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['file', 'console'],
            'level': 'INFO',
            'propagate': True,
        },
        'deals': {
            'handlers': ['file', 'console'],
            'level': 'DEBUG',
            'propagate': True,
        },
    },
}
```

### Debugging Tools

```python
# Use ipdb for debugging
import ipdb; ipdb.set_trace()

# Use Django shell for testing
python manage.py shell

# Use Django extensions for advanced shell
python manage.py shell_plus

# Print SQL queries
from django.db import connection
print(connection.queries)

# Use Django's logging
import logging
logger = logging.getLogger(__name__)
logger.debug("Debug message")
```

## Performance Optimization

### Database Optimization

```python
# Use select_related for foreign keys
deals = Deal.objects.select_related('client', 'organization')

# Use prefetch_related for reverse foreign keys
deals = Deal.objects.prefetch_related('payments')

# Use only() to limit fields
deals = Deal.objects.only('id', 'deal_id', 'amount')

# Use defer() to exclude fields
deals = Deal.objects.defer('description')

# Use bulk operations
Deal.objects.bulk_create(deals_list)
Deal.objects.bulk_update(deals_list, ['status'])

# Use raw SQL for complex queries
deals = Deal.objects.raw(
    'SELECT * FROM deals_deal WHERE amount > %s',
    [1000]
)
```

### API Optimization

```python
# Use pagination
class DealViewSet(viewsets.ModelViewSet):
    pagination_class = PageNumberPagination
    page_size = 25

# Use caching
from django.views.decorators.cache import cache_page
from django.utils.decorators import method_decorator

@method_decorator(cache_page(60 * 5), name='list')
class DealViewSet(viewsets.ModelViewSet):
    pass

# Use filtering instead of Python filtering
deals = Deal.objects.filter(amount__gte=1000)  # Good
deals = [d for d in Deal.objects.all() if d.amount >= 1000]  # Bad
```

### Caching Strategy

```python
# Cache expensive calculations
from django.core.cache import cache

def get_deal_statistics(organization_id):
    cache_key = f'deal_stats_{organization_id}'
    stats = cache.get(cache_key)
    
    if stats is None:
        stats = calculate_deal_statistics(organization_id)
        cache.set(cache_key, stats, 300)  # 5 minutes
    
    return stats

# Invalidate cache when needed
def update_deal_statistics(organization_id):
    cache_key = f'deal_stats_{organization_id}'
    cache.delete(cache_key)
```

## Security Guidelines

### Input Validation

```python
# Always validate user input
def validate_amount(value):
    if value <= 0:
        raise ValidationError("Amount must be positive")
    if value > 1000000:
        raise ValidationError("Amount exceeds maximum limit")
    return value

# Use DRF serializers for validation
class DealSerializer(serializers.ModelSerializer):
    def validate_amount(self, value):
        return validate_amount(value)
```

### Permission Checks

```python
# Always check permissions
def update_deal(request, deal_id):
    deal = get_object_or_404(Deal, id=deal_id)
    
    # Check organization isolation
    if deal.organization != request.user.organization:
        raise PermissionDenied("Access denied")
    
    # Check specific permissions
    if not request.user.has_perm('deals.change_deal'):
        raise PermissionDenied("Insufficient permissions")
```

### SQL Injection Prevention

```python
# Use Django ORM (automatically escaped)
deals = Deal.objects.filter(client__name=client_name)

# If using raw SQL, use parameterized queries
deals = Deal.objects.raw(
    'SELECT * FROM deals_deal WHERE client_id = %s',
    [client_id]
)

# Never use string formatting
# BAD: Deal.objects.raw(f'SELECT * FROM deals_deal WHERE client_id = {client_id}')
```

### File Upload Security

```python
# Validate file uploads
def validate_file_upload(file):
    # Check file size
    if file.size > 5 * 1024 * 1024:  # 5MB
        raise ValidationError("File too large")
    
    # Check file type
    allowed_types = ['image/jpeg', 'image/png', 'application/pdf']
    if file.content_type not in allowed_types:
        raise ValidationError("Invalid file type")
    
    # Check file extension
    import os
    ext = os.path.splitext(file.name)[1].lower()
    if ext not in ['.jpg', '.jpeg', '.png', '.pdf']:
        raise ValidationError("Invalid file extension")
```

## Contribution Guidelines

### Git Workflow

```bash
# Create feature branch
git checkout -b feature/new-feature

# Make changes and commit
git add .
git commit -m "Add new feature"

# Push to remote
git push origin feature/new-feature

# Create pull request
# Use GitHub/GitLab interface
```

### Commit Message Format

```
type(scope): subject

body

footer
```

Examples:
```
feat(deals): add payment verification endpoint

Add new endpoint for verifying payments with proper
authentication and permission checks.

Closes #123
```

### Pull Request Guidelines

1. Create descriptive PR title
2. Include detailed description
3. Add tests for new functionality
4. Update documentation
5. Ensure CI passes
6. Request code review

### Code Review Checklist

- [ ] Code follows style guidelines
- [ ] Tests are included and passing
- [ ] Documentation is updated
- [ ] Security considerations addressed
- [ ] Performance implications considered
- [ ] Error handling implemented
- [ ] Logging added where appropriate

## Tools and Utilities

### Management Commands

```bash
# Database management
python manage.py migrate
python manage.py createsuperuser
python manage.py flush

# Development helpers
python manage.py shell
python manage.py shell_plus
python manage.py runserver_plus

# Testing
python manage.py test
python manage.py test --keepdb

# Data management
python manage.py dumpdata > backup.json
python manage.py loaddata backup.json

# Custom commands
python manage.py seed_demo_data
python manage.py cleanup_test_data
python manage.py setup_permissions
```

### Useful Extensions

```bash
# Django Extensions
pip install django-extensions

# Provides enhanced shell, graph models, etc.
python manage.py shell_plus
python manage.py graph_models -a -o models.png

# Django Debug Toolbar
pip install django-debug-toolbar

# Provides detailed debug information
```

### Database Tools

```bash
# Database shell
python manage.py dbshell

# Show migrations
python manage.py showmigrations

# Create migration
python manage.py makemigrations

# SQL for migration
python manage.py sqlmigrate deals 0001

# Check for issues
python manage.py check
```

This development guide provides comprehensive guidelines for working on the Backend_PRS project. Follow these practices to maintain code quality, security, and performance standards.