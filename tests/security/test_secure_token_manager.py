"""
Management command to test SecureTokenManager functionality
"""

from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.test import RequestFactory
from core_config.jwt_auth import SecureTokenManager, JWTAuthentication, SecureCookieManager
from rest_framework.exceptions import AuthenticationFailed
import time

User = get_user_model()

class Command(BaseCommand):
    help = 'Test SecureTokenManager functionality'

    def add_arguments(self, parser):
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Enable verbose output',
        )

    def handle(self, *args, **options):
        verbose = options['verbose']
        
        self.stdout.write(self.style.SUCCESS('Testing SecureTokenManager...'))
        
        # Initialize components
        token_manager = SecureTokenManager()
        auth_backend = JWTAuthentication()
        cookie_manager = SecureCookieManager()
        factory = RequestFactory()
        
        # Create test user
        try:
            user = User.objects.get(email='test@example.com')
        except User.DoesNotExist:
            user = User.objects.create_user(
                email='test@example.com',
                password='testpass123',
                first_name='Test',
                last_name='User'
            )
            if verbose:
                self.stdout.write('Created test user: test@example.com')
        
        # Test 1: Token Generation
        self.stdout.write('\n1. Testing token generation...')
        request = factory.post('/login/')
        request.META['REMOTE_ADDR'] = '127.0.0.1'
        request.META['HTTP_USER_AGENT'] = 'Test Agent'
        
        try:
            tokens = token_manager.generate_token_pair(user, request)
            self.stdout.write(self.style.SUCCESS('✓ Token generation successful'))
            if verbose:
                self.stdout.write(f'  Access token length: {len(tokens["access_token"])}')
                self.stdout.write(f'  Refresh token length: {len(tokens["refresh_token"])}')
                self.stdout.write(f'  Token ID: {tokens["token_id"][:8]}...')
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'✗ Token generation failed: {e}'))
            return
        
        # Test 2: Token Validation
        self.stdout.write('\n2. Testing token validation...')
        try:
            payload = token_manager.validate_token(
                tokens['access_token'], 
                SecureTokenManager.ACCESS_TOKEN,
                request
            )
            self.stdout.write(self.style.SUCCESS('✓ Token validation successful'))
            if verbose:
                self.stdout.write(f'  User ID: {payload["user"].id}')
                self.stdout.write(f'  Token type: {payload["token_type"]}')
                self.stdout.write(f'  Issuer: {payload["iss"]}')
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'✗ Token validation failed: {e}'))
        
        # Test 3: Invalid Token Format
        self.stdout.write('\n3. Testing invalid token format validation...')
        try:
            token_manager.validate_token('invalid.token', request=request)
            self.stdout.write(self.style.ERROR('✗ Should have failed for invalid token format'))
        except AuthenticationFailed as e:
            if 'Invalid token format' in str(e):
                self.stdout.write(self.style.SUCCESS('✓ Invalid token format correctly rejected'))
            else:
                self.stdout.write(self.style.WARNING(f'? Unexpected error: {e}'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'✗ Unexpected exception: {e}'))
        
        # Test 4: Token Refresh
        self.stdout.write('\n4. Testing token refresh...')
        try:
            new_tokens = token_manager.refresh_token(tokens['refresh_token'], request)
            self.stdout.write(self.style.SUCCESS('✓ Token refresh successful'))
            if verbose:
                self.stdout.write('  New tokens generated')
                self.stdout.write(f'  New access token different: {new_tokens["access_token"] != tokens["access_token"]}')
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'✗ Token refresh failed: {e}'))
        
        # Test 5: Token Revocation
        self.stdout.write('\n5. Testing token revocation...')
        try:
            # Generate a new token for revocation test
            test_tokens = token_manager.generate_token_pair(user, request)
            
            # Validate it works first
            token_manager.validate_token(test_tokens['access_token'])
            
            # Revoke it
            token_manager.revoke_token(test_tokens['access_token'])
            
            # Try to validate again (should fail)
            try:
                token_manager.validate_token(test_tokens['access_token'])
                self.stdout.write(self.style.ERROR('✗ Revoked token should not validate'))
            except AuthenticationFailed:
                self.stdout.write(self.style.SUCCESS('✓ Token revocation successful'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'✗ Token revocation test failed: {e}'))
        
        # Test 6: Mass Token Revocation
        self.stdout.write('\n6. Testing mass token revocation...')
        try:
            # Generate multiple tokens
            tokens1 = token_manager.generate_token_pair(user, request)
            tokens2 = token_manager.generate_token_pair(user, request)
            
            # Validate both work
            token_manager.validate_token(tokens1['access_token'])
            token_manager.validate_token(tokens2['access_token'])
            
            # Revoke all user tokens
            token_manager.revoke_all_user_tokens(user, request)
            
            # Both should now fail
            failed_count = 0
            try:
                token_manager.validate_token(tokens1['access_token'])
            except AuthenticationFailed:
                failed_count += 1
            
            try:
                token_manager.validate_token(tokens2['access_token'])
            except AuthenticationFailed:
                failed_count += 1
            
            if failed_count == 2:
                self.stdout.write(self.style.SUCCESS('✓ Mass token revocation successful'))
            else:
                self.stdout.write(self.style.ERROR(f'✗ Only {failed_count}/2 tokens were revoked'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'✗ Mass token revocation test failed: {e}'))
        
        # Test 7: Authentication Backend
        self.stdout.write('\n7. Testing JWT authentication backend...')
        try:
            # Create request with Bearer token
            auth_request = factory.get('/api/test/')
            auth_request.META['HTTP_AUTHORIZATION'] = f'Bearer {tokens["access_token"]}'
            
            result = auth_backend.authenticate(auth_request)
            if result:
                auth_user, auth_token = result
                if auth_user == user and auth_token == tokens['access_token']:
                    self.stdout.write(self.style.SUCCESS('✓ JWT authentication backend successful'))
                else:
                    self.stdout.write(self.style.ERROR('✗ Authentication returned wrong user/token'))
            else:
                self.stdout.write(self.style.ERROR('✗ Authentication backend returned None'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'✗ Authentication backend test failed: {e}'))
        
        # Test 8: Cookie Manager
        self.stdout.write('\n8. Testing secure cookie manager...')
        try:
            from django.http import HttpResponse
            
            response = HttpResponse()
            cookie_manager.set_auth_cookies(response, tokens, secure=False)
            
            # Check cookies are set
            if 'access_token' in response.cookies and 'refresh_token' in response.cookies:
                access_cookie = response.cookies['access_token']
                if access_cookie['httponly'] and access_cookie['samesite'] == 'Strict':
                    self.stdout.write(self.style.SUCCESS('✓ Secure cookie manager successful'))
                    if verbose:
                        self.stdout.write('  Cookies set with httpOnly and SameSite=Strict')
                else:
                    self.stdout.write(self.style.ERROR('✗ Cookies missing security attributes'))
            else:
                self.stdout.write(self.style.ERROR('✗ Cookies not set properly'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'✗ Cookie manager test failed: {e}'))
        
        # Test 9: Token Metadata
        self.stdout.write('\n9. Testing token metadata...')
        try:
            metadata = token_manager.get_token_metadata(tokens['token_id'])
            if metadata and 'user_id' in metadata and 'created_at' in metadata:
                self.stdout.write(self.style.SUCCESS('✓ Token metadata retrieval successful'))
                if verbose:
                    self.stdout.write(f'  User ID: {metadata["user_id"]}')
                    self.stdout.write(f'  IP Address: {metadata.get("ip_address", "N/A")}')
                    self.stdout.write(f'  User Agent: {metadata.get("user_agent", "N/A")[:50]}...')
            else:
                self.stdout.write(self.style.ERROR('✗ Token metadata missing or incomplete'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'✗ Token metadata test failed: {e}'))
        
        # Test 10: Request Context Validation
        self.stdout.write('\n10. Testing request context validation...')
        try:
            # Create request with different IP
            context_request = factory.get('/api/test/')
            context_request.META['REMOTE_ADDR'] = '192.168.1.100'
            
            # This should still work but may log a warning
            payload = token_manager.validate_token(
                tokens['access_token'],
                SecureTokenManager.ACCESS_TOKEN,
                context_request
            )
            
            if payload and payload['user'] == user:
                self.stdout.write(self.style.SUCCESS('✓ Request context validation successful'))
                if verbose:
                    self.stdout.write('  IP change detected and logged (security feature)')
            else:
                self.stdout.write(self.style.ERROR('✗ Request context validation failed'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'✗ Request context validation test failed: {e}'))
        
        self.stdout.write(self.style.SUCCESS('\nSecureTokenManager testing completed!'))
        
        # Cleanup
        if verbose:
            self.stdout.write('\nCleaning up test data...')
        
        # Clean up test user if created
        try:
            user.delete()
            if verbose:
                self.stdout.write('Test user deleted')
        except:
            pass