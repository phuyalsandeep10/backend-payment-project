from django.core.management.base import BaseCommand
from django.db import transaction
from authentication.models import User
from organization.models import Organization
from deals.models import Deal, Payment, ActivityLog
from clients.models import Client
from permissions.models import Role
from django.db.models import Q


class Command(BaseCommand):
    help = 'Cleanup test data for API testing'

    def add_arguments(self, parser):
        parser.add_argument(
            '--org-name',
            type=str,
            default='Apex Innovations Inc.',
            help='Name of the test organization to clean up'
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force cleanup even if deals exist'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be deleted without actually deleting'
        )

    def handle(self, *args, **options):
        org_name = options['org_name']
        force = options['force']
        dry_run = options['dry_run']

        # Find ALL organizations with the test name (in case of duplicates)
        orgs_to_delete = Organization.objects.filter(name=org_name)
        
        if not orgs_to_delete.exists():
            self.stdout.write(
                self.style.WARNING(f'Organization "{org_name}" not found. Nothing to clean up.')
            )
            return

        self.stdout.write(f'Found {orgs_to_delete.count()} organization(s) named "{org_name}"')

        total_counts = {
            'activity_logs': 0,
            'payments': 0,
            'deals': 0,
            'clients': 0,
            'users': 0,
            'roles': 0,
            'organizations': orgs_to_delete.count()
        }

        # Count objects across all matching organizations
        counts = {
            'activity_logs': ActivityLog.objects.filter(deal__organization__in=orgs_to_delete).count(),
            'payments': Payment.objects.filter(deal__organization__in=orgs_to_delete).count(),
            'deals': Deal.objects.filter(organization__in=orgs_to_delete).count(),
            'clients': Client.objects.filter(organization__in=orgs_to_delete).count(),
            'users': User.objects.filter(organization__in=orgs_to_delete).count(),
            'roles': Role.objects.filter(organization__in=orgs_to_delete).count(),
            'organizations': orgs_to_delete.count()
        }
        
        # Count existing objects
        activity_count = ActivityLog.objects.filter(deal__organization__in=orgs_to_delete).count()
        payment_count = Payment.objects.filter(deal__organization__in=orgs_to_delete).count()
        deal_count = Deal.objects.filter(organization__in=orgs_to_delete).count()
        client_count = Client.objects.filter(organization__in=orgs_to_delete).count()
        user_count = User.objects.filter(organization__in=orgs_to_delete).count()
        role_count = Role.objects.filter(organization__in=orgs_to_delete).count()
        
        # Also count orphaned test users (users with test email patterns but no organization)
        test_email_patterns = ['sales.user@apexinc.com', 'verifier.user@apexinc.com', 'head.user@apexinc.com', 'member.user@apexinc.com', 'org.admin@apexinc.com']
        orphaned_users = User.objects.filter(email__in=test_email_patterns, organization__isnull=True)
        orphaned_user_count = orphaned_users.count()
        
        total_user_count = user_count + orphaned_user_count

        # Count objects across all matching organizations
        counts = {
            'activity_logs': activity_count,
            'payments': payment_count,
            'deals': deal_count,
            'clients': client_count,
            'users': total_user_count,
            'roles': role_count,
            'organizations': orgs_to_delete.count(),
            'orphaned_users': orphaned_user_count
        }

        self.stdout.write('\nTotal objects to be deleted:')
        for key, count in counts.items():
            self.stdout.write(f'  - {key.replace("_", " ").title()}: {count}')

        if counts['deals'] > 0 and not force:
            self.stdout.write(
                self.style.ERROR(
                    '\nDeals exist for these organizations. Use --force to proceed with cleanup.'
                )
            )
            return

        if dry_run:
            self.stdout.write(
                self.style.SUCCESS('\nDry run completed. Use without --dry-run to actually delete.')
            )
            return

        # Perform cleanup for each organization
        total_deleted = {
            'activity_logs': 0,
            'payments': 0,
            'deals': 0,
            'clients': 0,
            'users': 0,
            'roles': 0,
            'organizations': 0
        }

        with transaction.atomic():
            try:
                for org in orgs_to_delete:
                    self.stdout.write(f'\nProcessing organization: {org.name} (ID: {org.id})')
                    
                    # Step 1: Delete activity logs
                    deleted_logs = ActivityLog.objects.filter(deal__organization=org).delete()
                    total_deleted['activity_logs'] += deleted_logs[0] if deleted_logs[0] else 0
                    
                    # Step 2: Delete payments
                    deleted_payments = Payment.objects.filter(deal__organization=org).delete()
                    total_deleted['payments'] += deleted_payments[0] if deleted_payments[0] else 0
                    
                    # Step 3: Delete deals using raw SQL to bypass PROTECT constraint
                    deals_to_delete = Deal.objects.filter(organization=org)
                    if deals_to_delete.exists():
                        from django.db import connection
                        with connection.cursor() as cursor:
                            deals_count = deals_to_delete.count()
                            cursor.execute(
                                "DELETE FROM deals_deal WHERE organization_id = %s",
                                [org.id]
                            )
                            total_deleted['deals'] += deals_count
                    
                    # Step 4: Delete clients
                    deleted_clients = Client.objects.filter(organization=org).delete()
                    total_deleted['clients'] += deleted_clients[0] if deleted_clients[0] else 0
                    
                    # Step 5: Delete users
                    deleted_users = User.objects.filter(organization=org).delete()
                    total_deleted['users'] += deleted_users[0] if deleted_users[0] else 0
                    
                    # Step 6: Delete roles
                    deleted_roles = Role.objects.filter(organization=org).delete()
                    total_deleted['roles'] += deleted_roles[0] if deleted_roles[0] else 0
                    
                    # Step 7: Delete the organization
                    org.delete()
                    total_deleted['organizations'] += 1

                # Step 8: Clean up orphaned test users (users with test patterns but no organization)
                test_email_patterns = ['sales.user@apexinc.com', 'verifier.user@apexinc.com', 'head.user@apexinc.com', 'member.user@apexinc.com', 'org.admin@apexinc.com']
                orphaned_users = User.objects.filter(email__in=test_email_patterns, organization__isnull=True)
                orphaned_count = orphaned_users.count()
                if orphaned_count > 0:
                    self.stdout.write(f'\nCleaning up {orphaned_count} orphaned test users...')
                    orphaned_users.delete()
                    total_deleted['users'] += orphaned_count

                self.stdout.write(f'\n{"="*50}')
                self.stdout.write('CLEANUP SUMMARY:')
                for key, count in total_deleted.items():
                    self.stdout.write(f'  {key.replace("_", " ").title()}: {count}')

                self.stdout.write(
                    self.style.SUCCESS(f'\nCleanup completed successfully! Deleted {total_deleted["organizations"]} organization(s).')
                )

            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'\nError during cleanup: {str(e)}')
                )
                raise 