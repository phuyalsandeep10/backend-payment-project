"""
Test Atomic Financial Operations
Management command to test and demonstrate atomic operations functionality
"""

from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import datetime, timedelta
from decimal import Decimal
from deals.models import Deal, Payment
from commission.models import Commission
from deals.atomic_operations import AtomicFinancialOperations
from organization.models import Organization
from authentication.models import User
import logging
import threading
import time

logger = logging.getLogger('atomic_test')

class Command(BaseCommand):
    help = 'Test atomic financial operations and race condition prevention'

    def add_arguments(self, parser):
        parser.add_argument(
            '--test-type',
            type=str,
            choices=['deal-status', 'payment-creation', 'commission-calc', 'optimistic-lock', 'race-condition'],
            required=True,
            help='Type of atomic operation test to run'
        )
        
        parser.add_argument(
            '--organization-id',
            type=int,
            help='Organization ID to use for testing'
        )
        
        parser.add_argument(
            '--deal-id',
            type=str,
            help='Deal ID to use for testing'
        )
        
        parser.add_argument(
            '--commission-id',
            type=int,
            help='Commission ID to use for testing'
        )
        
        parser.add_argument(
            '--concurrent-threads',
            type=int,
            default=5,
            help='Number of concurrent threads for race condition testing'
        )

    def handle(self, *args, **options):
        test_type = options['test_type']
        organization_id = options.get('organization_id')
        deal_id = options.get('deal_id')
        commission_id = options.get('commission_id')
        concurrent_threads = options.get('concurrent_threads', 5)
        
        self.stdout.write(f"Running atomic operations test: {test_type}")
        
        # Get test organization
        if organization_id:
            try:
                organization = Organization.objects.get(id=organization_id)
            except Organization.DoesNotExist:
                self.stdout.write(
                    self.style.ERROR(f'Organization with ID {organization_id} not found')
                )
                return
        else:
            organization = Organization.objects.first()
            if not organization:
                self.stdout.write(self.style.ERROR('No organizations found'))
                return
        
        # Get test user
        test_user = User.objects.filter(organization=organization, is_active=True).first()
        if not test_user:
            self.stdout.write(self.style.ERROR('No active users found in organization'))
            return
        
        try:
            if test_type == 'deal-status':
                self.test_deal_status_change(deal_id, test_user)
            elif test_type == 'payment-creation':
                self.test_payment_creation(deal_id, test_user)
            elif test_type == 'commission-calc':
                self.test_commission_calculation(commission_id, test_user)
            elif test_type == 'optimistic-lock':
                self.test_optimistic_locking(deal_id)
            elif test_type == 'race-condition':
                self.test_race_conditions(deal_id, concurrent_threads, test_user)
                
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Test failed: {str(e)}')
            )
            logger.error(f"Atomic operations test failed: {str(e)}")

    def test_deal_status_change(self, deal_id, user):
        """Test atomic deal status changes"""
        self.stdout.write("Testing atomic deal status changes...")
        
        if not deal_id:
            # Get a test deal
            deal = Deal.objects.filter(organization=user.organization).first()
            if not deal:
                self.stdout.write(self.style.ERROR('No deals found for testing'))
                return
            deal_id = str(deal.id)
        
        try:
            # Test verification status change
            result = AtomicFinancialOperations.atomic_deal_status_change(
                deal_id=deal_id,
                new_verification_status='verified',
                user=user
            )
            
            self.stdout.write(f"  Status change result: {result}")
            
            # Test verification workflow
            workflow_result = AtomicFinancialOperations.atomic_deal_verification_workflow(
                deal_id=deal_id,
                verification_decision='verified',
                verification_notes='Test verification',
                user=user
            )
            
            self.stdout.write(f"  Workflow result: {workflow_result}")
            self.stdout.write(self.style.SUCCESS("Deal status change test completed"))
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Deal status change test failed: {str(e)}"))

    def test_payment_creation(self, deal_id, user):
        """Test atomic payment creation"""
        self.stdout.write("Testing atomic payment creation...")
        
        if not deal_id:
            # Get a test deal
            deal = Deal.objects.filter(organization=user.organization).first()
            if not deal:
                self.stdout.write(self.style.ERROR('No deals found for testing'))
                return
            deal_id = str(deal.id)
        
        try:
            payment_data = {
                'received_amount': '100.00',
                'payment_date': timezone.now().date(),
                'payment_type': 'bank',
                'payment_category': 'partial',
                'payment_remarks': 'Test payment'
            }
            
            result = AtomicFinancialOperations.atomic_payment_creation(
                deal_id=deal_id,
                payment_data=payment_data,
                user=user
            )
            
            self.stdout.write(f"  Payment creation result: {result}")
            self.stdout.write(self.style.SUCCESS("Payment creation test completed"))
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Payment creation test failed: {str(e)}"))

    def test_commission_calculation(self, commission_id, user):
        """Test atomic commission calculation"""
        self.stdout.write("Testing atomic commission calculation...")
        
        if not commission_id:
            # Get a test commission
            commission = Commission.objects.filter(organization=user.organization).first()
            if not commission:
                self.stdout.write(self.style.ERROR('No commissions found for testing'))
                return
            commission_id = commission.id
        
        try:
            result = AtomicFinancialOperations.atomic_commission_calculation(
                commission_id=commission_id,
                recalculate_sales=True,
                user=user
            )
            
            self.stdout.write(f"  Commission calculation result: {result}")
            self.stdout.write(self.style.SUCCESS("Commission calculation test completed"))
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Commission calculation test failed: {str(e)}"))

    def test_optimistic_locking(self, deal_id):
        """Test optimistic locking functionality"""
        self.stdout.write("Testing optimistic locking...")
        
        if not deal_id:
            # Get a test deal
            deal = Deal.objects.first()
            if not deal:
                self.stdout.write(self.style.ERROR('No deals found for testing'))
                return
            deal_id = str(deal.id)
        
        try:
            # Get the deal
            deal = Deal.objects.get(id=deal_id)
            original_version = deal.lock_version
            
            self.stdout.write(f"  Original lock version: {original_version}")
            
            # Test successful optimistic lock save
            deal.deal_remarks = f"Updated at {timezone.now()}"
            deal.save_with_optimistic_lock()
            
            self.stdout.write(f"  New lock version: {deal.lock_version}")
            
            # Test concurrent modification detection
            concurrent_modification = deal.refresh_with_lock_check()
            self.stdout.write(f"  Concurrent modification detected: {concurrent_modification}")
            
            self.stdout.write(self.style.SUCCESS("Optimistic locking test completed"))
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Optimistic locking test failed: {str(e)}"))

    def test_race_conditions(self, deal_id, num_threads, user):
        """Test race condition prevention with concurrent operations"""
        self.stdout.write(f"Testing race condition prevention with {num_threads} concurrent threads...")
        
        if not deal_id:
            # Get a test deal
            deal = Deal.objects.filter(organization=user.organization).first()
            if not deal:
                self.stdout.write(self.style.ERROR('No deals found for testing'))
                return
            deal_id = str(deal.id)
        
        results = []
        errors = []
        
        def concurrent_operation(thread_id):
            """Function to run in each thread"""
            try:
                # Simulate concurrent payment creation
                payment_data = {
                    'received_amount': '10.00',
                    'payment_date': timezone.now().date(),
                    'payment_type': 'bank',
                    'payment_category': 'partial',
                    'payment_remarks': f'Concurrent test payment {thread_id}'
                }
                
                result = AtomicFinancialOperations.atomic_payment_creation(
                    deal_id=deal_id,
                    payment_data=payment_data,
                    user=user
                )
                
                results.append({
                    'thread_id': thread_id,
                    'success': True,
                    'result': result
                })
                
            except Exception as e:
                errors.append({
                    'thread_id': thread_id,
                    'error': str(e)
                })
        
        # Create and start threads
        threads = []
        for i in range(num_threads):
            thread = threading.Thread(target=concurrent_operation, args=(i,))
            threads.append(thread)
        
        # Start all threads
        start_time = time.time()
        for thread in threads:
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        end_time = time.time()
        
        # Report results
        self.stdout.write(f"  Concurrent operations completed in {end_time - start_time:.2f} seconds")
        self.stdout.write(f"  Successful operations: {len(results)}")
        self.stdout.write(f"  Failed operations: {len(errors)}")
        
        if results:
            self.stdout.write("  Sample successful results:")
            for result in results[:3]:
                self.stdout.write(f"    Thread {result['thread_id']}: Payment ID {result['result']['payment_id']}")
        
        if errors:
            self.stdout.write("  Errors encountered:")
            for error in errors[:3]:
                self.stdout.write(f"    Thread {error['thread_id']}: {error['error']}")
        
        self.stdout.write(self.style.SUCCESS("Race condition test completed"))