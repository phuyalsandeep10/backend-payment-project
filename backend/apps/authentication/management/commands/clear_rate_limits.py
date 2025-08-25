from django.core.management.base import BaseCommand
from django.core.cache import cache

class Command(BaseCommand):
    help = 'Clear rate limiting cache for testing purposes'

    def handle(self, *args, **options):
        try:
            # Clear all cache
            cache.clear()
            self.stdout.write(
                self.style.SUCCESS('✅ Successfully cleared rate limiting cache!')
            )
            self.stdout.write('📝 You can now try authentication again.')
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'❌ Error clearing cache: {e}')
            )
            self.stdout.write('💡 You may need to restart the Django server.')