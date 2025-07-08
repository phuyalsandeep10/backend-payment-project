"""
Test Shared Access Command

This command helps you test and debug shared access issues
when colleagues try to access your VS Code dev tunnel.
"""

import requests
import json
from django.core.management.base import BaseCommand
from django.conf import settings


class Command(BaseCommand):
    help = 'Test shared access to your API for colleagues'

    def add_arguments(self, parser):
        parser.add_argument(
            '--url',
            type=str,
            help='The tunnel URL to test (e.g., https://abc123-8000.inc1.devtunnels.ms)',
        )
        parser.add_argument(
            '--test-auth',
            action='store_true',
            help='Test authentication endpoints',
        )
        parser.add_argument(
            '--test-cors',
            action='store_true',
            help='Test CORS headers',
        )

    def handle(self, *args, **options):
        tunnel_url = options['url']
        
        if not tunnel_url:
            self.stdout.write(
                self.style.ERROR('❌ Please provide a tunnel URL with --url')
            )
            self.stdout.write('Example: python manage.py test_shared_access --url https://abc123-8000.inc1.devtunnels.ms')
            return
        
        if not tunnel_url.endswith('/'):
            tunnel_url += '/'
        
        self.stdout.write(
            self.style.SUCCESS('🌐 Testing Shared Access')
        )
        self.stdout.write('=' * 50)
        self.stdout.write(f'🎯 Testing URL: {tunnel_url}')
        self.stdout.write('')
        
        # Test basic connectivity
        self.test_basic_connectivity(tunnel_url)
        
        # Test CORS headers
        if options['test_cors']:
            self.test_cors_headers(tunnel_url)
        
        # Test authentication
        if options['test_auth']:
            self.test_authentication(tunnel_url)
        
        # Show configuration
        self.show_configuration()
        
        # Show troubleshooting tips
        self.show_troubleshooting_tips()

    def test_basic_connectivity(self, tunnel_url):
        """Test basic API connectivity"""
        self.stdout.write('🔍 Testing Basic Connectivity...')
        
        try:
            # Test API root
            api_url = f"{tunnel_url}api/v1/"
            response = requests.get(api_url, timeout=10)
            
            if response.status_code in [200, 401, 403]:
                self.stdout.write(
                    self.style.SUCCESS(f'✅ API Root: {response.status_code}')
                )
            else:
                self.stdout.write(
                    self.style.ERROR(f'❌ API Root: {response.status_code}')
                )
            
            # Test auth endpoint
            auth_url = f"{tunnel_url}api/v1/auth/"
            response = requests.get(auth_url, timeout=10)
            
            if response.status_code in [200, 401, 403]:
                self.stdout.write(
                    self.style.SUCCESS(f'✅ Auth Endpoint: {response.status_code}')
                )
            else:
                self.stdout.write(
                    self.style.ERROR(f'❌ Auth Endpoint: {response.status_code}')
                )
                
        except requests.exceptions.ConnectionError:
            self.stdout.write(
                self.style.ERROR('❌ Connection Error: Cannot reach the API')
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'❌ Error: {str(e)}')
            )
        
        self.stdout.write('')

    def test_cors_headers(self, tunnel_url):
        """Test CORS headers"""
        self.stdout.write('🔍 Testing CORS Headers...')
        
        try:
            # Test OPTIONS request (preflight)
            api_url = f"{tunnel_url}api/v1/auth/"
            headers = {
                'Origin': 'https://example.com',
                'Access-Control-Request-Method': 'POST',
                'Access-Control-Request-Headers': 'Content-Type,Authorization',
            }
            
            response = requests.options(api_url, headers=headers, timeout=10)
            
            cors_headers = {
                'Access-Control-Allow-Origin': response.headers.get('Access-Control-Allow-Origin'),
                'Access-Control-Allow-Methods': response.headers.get('Access-Control-Allow-Methods'),
                'Access-Control-Allow-Headers': response.headers.get('Access-Control-Allow-Headers'),
                'Access-Control-Allow-Credentials': response.headers.get('Access-Control-Allow-Credentials'),
            }
            
            self.stdout.write('📋 CORS Headers:')
            for header, value in cors_headers.items():
                if value:
                    self.stdout.write(f'   {header}: {value}')
                else:
                    self.stdout.write(f'   {header}: ❌ Missing')
            
            if response.status_code == 200:
                self.stdout.write(
                    self.style.SUCCESS('✅ CORS Preflight: OK')
                )
            else:
                self.stdout.write(
                    self.style.ERROR(f'❌ CORS Preflight: {response.status_code}')
                )
                
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'❌ CORS Test Error: {str(e)}')
            )
        
        self.stdout.write('')

    def test_authentication(self, tunnel_url):
        """Test authentication endpoints"""
        self.stdout.write('🔍 Testing Authentication...')
        
        try:
            # Test login endpoint
            login_url = f"{tunnel_url}api/v1/auth/login/"
            
            # Test with invalid credentials (should return 400 or 401)
            data = {
                'email': 'test@example.com',
                'password': 'wrongpassword'
            }
            
            response = requests.post(
                login_url, 
                json=data, 
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code in [400, 401, 403]:
                self.stdout.write(
                    self.style.SUCCESS(f'✅ Login Endpoint: {response.status_code} (Expected for invalid credentials)')
                )
            else:
                self.stdout.write(
                    self.style.WARNING(f'⚠️  Login Endpoint: {response.status_code} (Unexpected)')
                )
                
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'❌ Auth Test Error: {str(e)}')
            )
        
        self.stdout.write('')

    def show_configuration(self):
        """Show current configuration"""
        self.stdout.write('📊 Current Configuration:')
        self.stdout.write(f'   DEBUG: {settings.DEBUG}')
        self.stdout.write(f'   ALLOWED_HOSTS: {settings.ALLOWED_HOSTS}')
        self.stdout.write(f'   CORS_ALLOW_ALL_ORIGINS: {getattr(settings, "CORS_ALLOW_ALL_ORIGINS", "Not set")}')
        self.stdout.write(f'   CORS_ALLOW_CREDENTIALS: {getattr(settings, "CORS_ALLOW_CREDENTIALS", "Not set")}')
        self.stdout.write('')

    def show_troubleshooting_tips(self):
        """Show troubleshooting tips"""
        self.stdout.write('🔧 Troubleshooting Tips:')
        self.stdout.write('')
        
        self.stdout.write('1. 🔑 Authentication Issues:')
        self.stdout.write('   - Make sure your colleague has valid credentials')
        self.stdout.write('   - Check if the user exists in your database')
        self.stdout.write('   - Verify the user has proper permissions')
        self.stdout.write('')
        
        self.stdout.write('2. 🌐 CORS Issues:')
        self.stdout.write('   - Check browser console for CORS errors')
        self.stdout.write('   - Ensure frontend is sending proper headers')
        self.stdout.write('   - Verify Content-Type is application/json')
        self.stdout.write('')
        
        self.stdout.write('3. 🔗 Connection Issues:')
        self.stdout.write('   - Verify VS Code tunnel is active')
        self.stdout.write('   - Check if Django server is running')
        self.stdout.write('   - Ensure tunnel URL is correct')
        self.stdout.write('')
        
        self.stdout.write('4. 🛡️ Security Issues:')
        self.stdout.write('   - Check if IP is blocked by firewall')
        self.stdout.write('   - Verify rate limiting settings')
        self.stdout.write('   - Check security middleware logs')
        self.stdout.write('')
        
        self.stdout.write('5. 🧪 Testing Commands:')
        self.stdout.write('   # Test from colleague\'s machine:')
        self.stdout.write('   curl -X GET "YOUR_TUNNEL_URL/api/v1/"')
        self.stdout.write('   curl -X POST "YOUR_TUNNEL_URL/api/v1/auth/login/" \\')
        self.stdout.write('     -H "Content-Type: application/json" \\')
        self.stdout.write('     -d \'{"email":"test@example.com","password":"password"}\'')
        self.stdout.write('')
        
        self.stdout.write('6. 📝 Debug Information:')
        self.stdout.write('   # Check Django logs:')
        self.stdout.write('   tail -f logs/security.log')
        self.stdout.write('   # Check Django server console for errors')
        self.stdout.write('')
        
        self.stdout.write('=' * 50)
        self.stdout.write(
            self.style.SUCCESS('✅ Run this command to test specific issues!')
        ) 