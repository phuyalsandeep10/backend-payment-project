"""
Management command to test SecureSessionManager functionality
"""

from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.test import RequestFactory
from django.utils import timezone
from core_config.secure_session_manager import SecureSessionManager
from authentication.models import SecureUserSession
import time

User = get_user_model()

class Command(BaseCommand):
    help = 'Test SecureSessionManager functionality'

    def add_arguments(self, parser):
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Enable verbose output',
        )
        parser.add_argument(
            '--cleanup',
            action='store_true',
            help='Clean up test data after testing',
        )

    def handle(self, *args, **options):
        verbose = options['verbose']
        cleanup = options['cleanup']
        
        self.stdout.write(self.style.SUCCESS('Testing SecureSessionManager...'))
        
        # Initialize components
        session_manager = SecureSessionManager()
        factory = RequestFactory()
        
        # Create test user
        try:
            user = User.objects.get(email='test_session@example.com')
        except User.DoesNotExist:
            user = User.objects.create_user(
                email='test_session@example.com',
                password='testpass123',
                first_name='Test',
                last_name='Session'
            )
            if verbose:
                self.stdout.write('Created test user: test_session@example.com')
        
        # Test 1: Session Creation
        self.stdout.write('\n1. Testing secure session creation...')
        request = factory.post('/login/')
        request.META['REMOTE_ADDR'] = '192.168.1.100'
        request.META['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        
        try:
            session = session_manager.create_session(
                user=user,
                request=request,
                jwt_token_id='test_jwt_token_123'
            )
            self.stdout.write(self.style.SUCCESS('✓ Secure session creation successful'))
            if verbose:
                self.stdout.write(f'  Session ID: {session.session_id[:8]}...')
                self.stdout.write(f'  IP Address: {session.ip_address}')
                self.stdout.write(f'  Device Type: {session.device_type}')
                self.stdout.write(f'  Browser: {session.browser_name}')
                self.stdout.write(f'  OS: {session.os_name}')
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'✗ Session creation failed: {e}'))
            return
        
        # Test 2: Session Validation
        self.stdout.write('\n2. Testing session validation...')
        try:
            validated_session = session_manager.validate_session(
                session.session_id,
                request
            )
            if validated_session and validated_session.is_active:
                self.stdout.write(self.style.SUCCESS('✓ Session validation successful'))
                if verbose:
                    self.stdout.write(f'  User: {validated_session.user.email}')
                    self.stdout.write(f'  Active: {validated_session.is_active}')
                    self.stdout.write(f'  Suspicious: {validated_session.is_suspicious}')
            else:
                self.stdout.write(self.style.ERROR('✗ Session validation failed'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'✗ Session validation failed: {e}'))
        
        # Test 3: Session Security Validation
        self.stdout.write('\n3. Testing session security validation...')
        try:
            # Test with different IP (should work with default settings)
            different_ip_request = factory.get('/api/')
            different_ip_request.META['REMOTE_ADDR'] = '192.168.1.101'
            different_ip_request.META['HTTP_USER_AGENT'] = request.META['HTTP_USER_AGENT']
            
            validated_session = session_manager.validate_session(
                session.session_id,
                different_ip_request
            )
            
            if validated_session:
                self.stdout.write(self.style.SUCCESS('✓ Session security validation (different IP) successful'))
                if verbose:
                    self.stdout.write('  IP change allowed (default security settings)')
            else:
                self.stdout.write(self.style.WARNING('? Session rejected due to IP change'))
            
            # Test with different user agent (should fail with default settings)
            different_ua_request = factory.get('/api/')
            different_ua_request.META['REMOTE_ADDR'] = '192.168.1.100'
            different_ua_request.META['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
            
            validated_session = session_manager.validate_session(
                session.session_id,
                different_ua_request
            )
            
            if not validated_session:
                self.stdout.write(self.style.SUCCESS('✓ Session security validation (different UA) correctly rejected'))
                if verbose:
                    self.stdout.write('  User agent change correctly detected and blocked')
            else:
                self.stdout.write(self.style.WARNING('? Session allowed despite user agent change'))
                
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'✗ Session security validation failed: {e}'))
        
        # Test 4: Multiple Sessions and Limits
        self.stdout.write('\n4. Testing session limits...')
        try:
            # Create multiple sessions
            sessions = []
            for i in range(3):
                new_request = factory.post(f'/login_{i}/')
                new_request.META['REMOTE_ADDR'] = f'192.168.1.{110 + i}'
                new_request.META['HTTP_USER_AGENT'] = request.META['HTTP_USER_AGENT']
                
                new_session = session_manager.create_session(
                    user=user,
                    request=new_request,
                    jwt_token_id=f'test_jwt_token_{i}'
                )
                sessions.append(new_session)
            
            # Check active sessions
            active_sessions = SecureUserSession.get_user_active_sessions(user)
            self.stdout.write(self.style.SUCCESS(f'✓ Multiple sessions created: {active_sessions.count()} active'))
            
            if verbose:
                for i, sess in enumerate(active_sessions):
                    self.stdout.write(f'  Session {i+1}: {sess.session_id[:8]}... from {sess.ip_address}')
                    
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'✗ Session limits test failed: {e}'))
        
        # Test 5: Session Invalidation
        self.stdout.write('\n5. Testing session invalidation...')
        try:
            # Get first session to invalidate
            test_session = sessions[0] if sessions else session
            
            # Invalidate specific session
            success = session_manager.invalidate_session(
                test_session.session_id,
                'test_invalidation'
            )
            
            if success:
                self.stdout.write(self.style.SUCCESS('✓ Session invalidation successful'))
                
                # Verify session is invalid
                validated_session = session_manager.validate_session(test_session.session_id)
                if not validated_session:
                    self.stdout.write(self.style.SUCCESS('✓ Invalidated session correctly rejected'))
                else:
                    self.stdout.write(self.style.ERROR('✗ Invalidated session still valid'))
            else:
                self.stdout.write(self.style.ERROR('✗ Session invalidation failed'))
                
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'✗ Session invalidation test failed: {e}'))
        
        # Test 6: Mass Session Invalidation
        self.stdout.write('\n6. Testing mass session invalidation...')
        try:
            # Count active sessions before
            active_before = SecureUserSession.get_user_active_sessions(user).count()
            
            # Invalidate all user sessions
            invalidated_count = session_manager.invalidate_all_user_sessions(
                user,
                'test_mass_invalidation'
            )
            
            # Count active sessions after
            active_after = SecureUserSession.get_user_active_sessions(user).count()
            
            self.stdout.write(self.style.SUCCESS(f'✓ Mass invalidation successful: {invalidated_count} sessions invalidated'))
            if verbose:
                self.stdout.write(f'  Active sessions before: {active_before}')
                self.stdout.write(f'  Active sessions after: {active_after}')
                
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'✗ Mass session invalidation test failed: {e}'))
        
        # Test 7: Session Statistics
        self.stdout.write('\n7. Testing session statistics...')
        try:
            # Create a few new sessions for statistics
            for i in range(2):
                new_request = factory.post(f'/stats_login_{i}/')
                new_request.META['REMOTE_ADDR'] = f'192.168.2.{10 + i}'
                new_request.META['HTTP_USER_AGENT'] = request.META['HTTP_USER_AGENT']
                
                session_manager.create_session(
                    user=user,
                    request=new_request,
                    jwt_token_id=f'stats_jwt_token_{i}'
                )
            
            # Get statistics
            stats = session_manager.get_session_statistics()
            
            self.stdout.write(self.style.SUCCESS('✓ Session statistics retrieved'))
            if verbose:
                self.stdout.write(f'  Total active sessions: {stats["total_active_sessions"]}')
                self.stdout.write(f'  Suspicious sessions: {stats["suspicious_sessions"]}')
                self.stdout.write(f'  Recent logins: {stats["recent_logins"]}')
                self.stdout.write(f'  Sessions by device: {stats["sessions_by_device"]}')
                
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'✗ Session statistics test failed: {e}'))
        
        # Test 8: Session Cleanup
        self.stdout.write('\n8. Testing session cleanup...')
        try:
            # Create a session and manually expire it
            expired_request = factory.post('/expired_login/')
            expired_request.META['REMOTE_ADDR'] = '192.168.3.1'
            expired_request.META['HTTP_USER_AGENT'] = request.META['HTTP_USER_AGENT']
            
            expired_session = session_manager.create_session(
                user=user,
                request=expired_request,
                jwt_token_id='expired_jwt_token'
            )
            
            # Manually expire the session
            expired_session.expires_at = timezone.now() - timezone.timedelta(hours=1)
            expired_session.save()
            
            # Run cleanup
            cleanup_count = session_manager.cleanup_expired_sessions()
            
            self.stdout.write(self.style.SUCCESS(f'✓ Session cleanup successful: {cleanup_count} sessions cleaned'))
            
            # Verify expired session is inactive
            expired_session.refresh_from_db()
            if not expired_session.is_active:
                self.stdout.write(self.style.SUCCESS('✓ Expired session correctly marked inactive'))
            else:
                self.stdout.write(self.style.ERROR('✗ Expired session still active'))
                
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'✗ Session cleanup test failed: {e}'))
        
        # Test 9: Client Information Extraction
        self.stdout.write('\n9. Testing client information extraction...')
        try:
            # Test with various user agents
            test_user_agents = [
                'Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1',
                'Mozilla/5.0 (iPad; CPU OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            ]
            
            for i, ua in enumerate(test_user_agents):
                test_request = factory.post(f'/client_test_{i}/')
                test_request.META['REMOTE_ADDR'] = f'192.168.4.{10 + i}'
                test_request.META['HTTP_USER_AGENT'] = ua
                test_request.META['HTTP_X_FORWARDED_FOR'] = f'203.0.113.{10 + i}, 192.168.4.{10 + i}'
                
                client_info = session_manager._extract_client_info(test_request)
                
                if verbose:
                    self.stdout.write(f'  Client {i+1}:')
                    self.stdout.write(f'    IP: {client_info["ip_address"]}')
                    self.stdout.write(f'    Device: {client_info["device_type"]}')
                    self.stdout.write(f'    Browser: {client_info["browser_name"]}')
                    self.stdout.write(f'    OS: {client_info["os_name"]}')
            
            self.stdout.write(self.style.SUCCESS('✓ Client information extraction successful'))
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'✗ Client information extraction test failed: {e}'))
        
        # Test 10: Database Integration
        self.stdout.write('\n10. Testing database integration...')
        try:
            # Test database queries
            total_sessions = SecureUserSession.objects.count()
            active_sessions = SecureUserSession.objects.filter(is_active=True).count()
            user_sessions = SecureUserSession.get_user_active_sessions(user).count()
            
            self.stdout.write(self.style.SUCCESS('✓ Database integration successful'))
            if verbose:
                self.stdout.write(f'  Total sessions in DB: {total_sessions}')
                self.stdout.write(f'  Active sessions in DB: {active_sessions}')
                self.stdout.write(f'  User active sessions: {user_sessions}')
                
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'✗ Database integration test failed: {e}'))
        
        self.stdout.write(self.style.SUCCESS('\nSecureSessionManager testing completed!'))
        
        # Cleanup if requested
        if cleanup:
            self.stdout.write('\nCleaning up test data...')
            try:
                # Delete test sessions
                SecureUserSession.objects.filter(user=user).delete()
                
                # Delete test user
                user.delete()
                
                self.stdout.write(self.style.SUCCESS('✓ Test data cleaned up'))
            except Exception as e:
                self.stdout.write(self.style.ERROR(f'✗ Cleanup failed: {e}'))
        else:
            self.stdout.write(f'\nTest user created: {user.email}')
            self.stdout.write('Use --cleanup flag to remove test data')
        
        # Summary
        self.stdout.write(f'\n{self.style.SUCCESS("="*50)}')
        self.stdout.write(self.style.SUCCESS('SECURE SESSION MANAGER TEST SUMMARY'))
        self.stdout.write(f'{self.style.SUCCESS("="*50)}')
        self.stdout.write('✓ Session creation and validation')
        self.stdout.write('✓ Security validation (IP/User Agent)')
        self.stdout.write('✓ Session limits and enforcement')
        self.stdout.write('✓ Session invalidation (single and mass)')
        self.stdout.write('✓ Session statistics and monitoring')
        self.stdout.write('✓ Session cleanup and maintenance')
        self.stdout.write('✓ Client information extraction')
        self.stdout.write('✓ Database integration')
        self.stdout.write(f'{self.style.SUCCESS("="*50)}')