"""
Management command for role cache operations and analytics
"""

from django.core.management.base import BaseCommand
from django.utils import timezone
from apps.organization.models import Organization
from apps.permissions.models import Role
from apps.authentication.models import User
from permissions.cache_service import RolePermissionCache
from django.db.models import Count, Q


class Command(BaseCommand):
    help = 'Manage role permission caches and generate analytics'

    def add_arguments(self, parser):
        parser.add_argument(
            '--organization',
            type=str,
            help='Specific organization name to manage'
        )
        parser.add_argument(
            '--action',
            type=str,
            choices=['warm', 'clear', 'stats', 'analytics'],
            default='stats',
            help='Action to perform: warm, clear, stats, or analytics'
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Show detailed output'
        )

    def handle(self, *args, **options):
        action = options['action']
        organization_name = options['organization']
        verbose = options['verbose']

        if organization_name:
            try:
                organization = Organization.objects.get(name=organization_name)
                organizations = [organization]
            except Organization.DoesNotExist:
                self.stdout.write(
                    self.style.ERROR(f"Organization '{organization_name}' not found")
                )
                return
        else:
            organizations = Organization.objects.all()

        if action == 'warm':
            self.warm_caches(organizations, verbose)
        elif action == 'clear':
            self.clear_caches(organizations, verbose)
        elif action == 'stats':
            self.show_cache_stats(organizations, verbose)
        elif action == 'analytics':
            self.show_role_analytics(organizations, verbose)

    def warm_caches(self, organizations, verbose):
        """Warm caches for organizations"""
        self.stdout.write(self.style.SUCCESS('Warming role permission caches...'))
        
        for org in organizations:
            if verbose:
                self.stdout.write(f"Warming cache for: {org.name}")
            
            RolePermissionCache.warm_organization_cache(org.id)
            
            if verbose:
                stats = RolePermissionCache.get_cache_stats(org.id)
                self.stdout.write(
                    f"  Cached items - Roles: {stats['cached_items']['roles']}, "
                    f"Users: {stats['cached_items']['users']}"
                )
        
        self.stdout.write(
            self.style.SUCCESS(f'Cache warming completed for {len(organizations)} organizations')
        )

    def clear_caches(self, organizations, verbose):
        """Clear caches for organizations"""
        self.stdout.write(self.style.WARNING('Clearing role permission caches...'))
        
        for org in organizations:
            if verbose:
                self.stdout.write(f"Clearing cache for: {org.name}")
            
            RolePermissionCache.invalidate_organization_cache(org.id)
        
        self.stdout.write(
            self.style.SUCCESS(f'Cache clearing completed for {len(organizations)} organizations')
        )

    def show_cache_stats(self, organizations, verbose):
        """Show cache statistics"""
        self.stdout.write(self.style.SUCCESS('Role Permission Cache Statistics'))
        self.stdout.write('=' * 50)
        
        total_cached_roles = 0
        total_cached_users = 0
        
        for org in organizations:
            stats = RolePermissionCache.get_cache_stats(org.id)
            
            self.stdout.write(f"\nOrganization: {org.name}")
            self.stdout.write(f"  Cached Roles: {stats['cached_items']['roles']}")
            self.stdout.write(f"  Cached Users: {stats['cached_items']['users']}")
            self.stdout.write(f"  Org Cache: {'Yes' if stats['cached_items']['permissions'] else 'No'}")
            
            total_cached_roles += stats['cached_items']['roles']
            total_cached_users += stats['cached_items']['users']
            
            if verbose:
                # Show detailed role information
                roles = Role.objects.filter(organization=org).annotate(
                    user_count=Count('users', filter=Q(users__is_active=True))
                )
                
                self.stdout.write("  Roles:")
                for role in roles:
                    cache_status = "Cached" if RolePermissionCache.get_role_permissions(role.id) else "Not Cached"
                    self.stdout.write(f"    {role.name}: {role.user_count} users ({cache_status})")
        
        self.stdout.write(f"\nTotal Summary:")
        self.stdout.write(f"  Organizations: {len(organizations)}")
        self.stdout.write(f"  Cached Roles: {total_cached_roles}")
        self.stdout.write(f"  Cached Users: {total_cached_users}")

    def show_role_analytics(self, organizations, verbose):
        """Show role usage analytics"""
        self.stdout.write(self.style.SUCCESS('Role Usage Analytics'))
        self.stdout.write('=' * 50)
        
        for org in organizations:
            self.stdout.write(f"\nOrganization: {org.name}")
            self.stdout.write('-' * 30)
            
            # Get role statistics
            roles = Role.objects.filter(organization=org).annotate(
                active_user_count=Count('users', filter=Q(users__is_active=True)),
                total_user_count=Count('users')
            ).order_by('-active_user_count')
            
            total_active_users = sum(role.active_user_count for role in roles)
            
            self.stdout.write(f"Total Active Users: {total_active_users}")
            self.stdout.write(f"Total Roles: {roles.count()}")
            
            if roles:
                most_used_role = roles.first()
                self.stdout.write(f"Most Used Role: {most_used_role.name} ({most_used_role.active_user_count} users)")
                
                unused_roles = [role for role in roles if role.active_user_count == 0]
                if unused_roles:
                    self.stdout.write(f"Unused Roles: {len(unused_roles)}")
                    if verbose:
                        for role in unused_roles:
                            self.stdout.write(f"  - {role.name}")
                
                self.stdout.write("\nRole Distribution:")
                for role in roles:
                    percentage = (role.active_user_count / total_active_users * 100) if total_active_users > 0 else 0
                    self.stdout.write(
                        f"  {role.name}: {role.active_user_count} users ({percentage:.1f}%)"
                    )
                    
                    if verbose and role.active_user_count > 0:
                        # Show permission count for this role
                        permission_count = role.permissions.count()
                        self.stdout.write(f"    Permissions: {permission_count}")
            
            # Show recent role assignments
            if verbose:
                recent_users = User.objects.filter(
                    organization=org,
                    is_active=True,
                    role__isnull=False
                ).select_related('role').order_by('-date_joined')[:5]
                
                if recent_users:
                    self.stdout.write("\nRecent Role Assignments:")
                    for user in recent_users:
                        self.stdout.write(
                            f"  {user.email} -> {user.role.name} "
                            f"(joined: {user.date_joined.strftime('%Y-%m-%d')})"
                        )
            
            # Performance recommendations
            self.stdout.write("\nRecommendations:")
            if len(unused_roles) > 2:
                self.stdout.write("  • Consider removing unused roles to simplify management")
            
            if total_active_users > 50:
                self.stdout.write("  • Consider using bulk role assignment for efficiency")
            
            if roles.count() > 10:
                self.stdout.write("  • Consider role consolidation to reduce complexity")
            
            # Cache recommendations
            cache_stats = RolePermissionCache.get_cache_stats(org.id)
            if cache_stats['cached_items']['roles'] < roles.count():
                self.stdout.write("  • Consider warming role caches for better performance")
        
        self.stdout.write(f"\nAnalytics generated at: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}")