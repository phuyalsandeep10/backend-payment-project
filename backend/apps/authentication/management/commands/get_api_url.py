"""
Get API URL Command

This command helps you get the correct API URL for your development environment,
especially useful when using VS Code dev tunnels or other tunneling services.
"""

import os
import socket
from django.core.management.base import BaseCommand
from django.conf import settings


class Command(BaseCommand):
    help = 'Get the correct API URL for your development environment'

    def add_arguments(self, parser):
        parser.add_argument(
            '--port',
            type=int,
            default=8000,
            help='Port number (default: 8000)',
        )
        parser.add_argument(
            '--protocol',
            type=str,
            choices=['http', 'https'],
            default='http',
            help='Protocol to use (default: http)',
        )

    def handle(self, *args, **options):
        port = options['port']
        protocol = options['protocol']
        
        self.stdout.write(
            self.style.SUCCESS('🌐 API URL Information')
        )
        self.stdout.write('=' * 50)
        
        # Get local IP address
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
        except Exception:
            local_ip = '127.0.0.1'
        
        # Display different URL options
        urls = [
            f"{protocol}://localhost:{port}/api/v1/",
            f"{protocol}://127.0.0.1:{port}/api/v1/",
            f"{protocol}://{local_ip}:{port}/api/v1/",
        ]
        
        self.stdout.write('\n📋 Available API URLs:')
        for i, url in enumerate(urls, 1):
            self.stdout.write(f"{i}. {url}")
        
        # Check for VS Code dev tunnel
        self.stdout.write('\n🔍 VS Code Dev Tunnel Detection:')
        if 'VSCODE_TUNNEL_URL' in os.environ:
            tunnel_url = os.environ['VSCODE_TUNNEL_URL']
            api_url = f"{tunnel_url}/api/v1/"
            self.stdout.write(
                self.style.SUCCESS(f"✅ Found VS Code tunnel: {api_url}")
            )
        else:
            self.stdout.write(
                self.style.WARNING("⚠️  No VS Code tunnel detected")
            )
        
        # Check for ngrok
        self.stdout.write('\n🔍 Ngrok Detection:')
        try:
            import requests
            response = requests.get('http://localhost:4040/api/tunnels', timeout=2)
            if response.status_code == 200:
                tunnels = response.json().get('tunnels', [])
                for tunnel in tunnels:
                    if tunnel.get('proto') == 'https':
                        api_url = f"{tunnel['public_url']}/api/v1/"
                        self.stdout.write(
                            self.style.SUCCESS(f"✅ Found ngrok tunnel: {api_url}")
                        )
                        break
                else:
                    self.stdout.write(
                        self.style.WARNING("⚠️  No HTTPS ngrok tunnel found")
                    )
            else:
                self.stdout.write(
                    self.style.WARNING("⚠️  Ngrok not running or not accessible")
                )
        except Exception:
            self.stdout.write(
                self.style.WARNING("⚠️  Ngrok not detected")
            )
        
        # Environment information
        self.stdout.write('\n📊 Environment Information:')
        self.stdout.write(f"DEBUG: {settings.DEBUG}")
        self.stdout.write(f"ALLOWED_HOSTS: {settings.ALLOWED_HOSTS}")
        
        # CORS information
        if hasattr(settings, 'CORS_ALLOW_ALL_ORIGINS'):
            self.stdout.write(f"CORS_ALLOW_ALL_ORIGINS: {settings.CORS_ALLOW_ALL_ORIGINS}")
        
        # Recommendations
        self.stdout.write('\n💡 Recommendations:')
        if settings.DEBUG:
            self.stdout.write("✅ DEBUG mode is enabled - all hosts are allowed")
            self.stdout.write("✅ CORS is configured to allow all origins")
        else:
            self.stdout.write("⚠️  DEBUG mode is disabled - check ALLOWED_HOSTS")
        
        # Frontend integration example
        self.stdout.write('\n🔗 Frontend Integration Example:')
        self.stdout.write('```javascript')
        self.stdout.write('// Use this URL in your frontend')
        self.stdout.write(f'const API_BASE_URL = "{urls[0]}";')
        self.stdout.write('')
        self.stdout.write('// Example API call')
        self.stdout.write('fetch(`${API_BASE_URL}auth/login/`, {')
        self.stdout.write('  method: "POST",')
        self.stdout.write('  headers: {')
        self.stdout.write('    "Content-Type": "application/json",')
        self.stdout.write('  },')
        self.stdout.write('  body: JSON.stringify({')
        self.stdout.write('    email: "user@example.com",')
        self.stdout.write('    password: "password"')
        self.stdout.write('  })')
        self.stdout.write('})')
        self.stdout.write('```')
        
        self.stdout.write('\n🎯 Quick Test:')
        self.stdout.write(f'curl -X GET "{urls[0]}"')
        
        self.stdout.write('\n' + '=' * 50)
        self.stdout.write(
            self.style.SUCCESS('✅ Use any of the above URLs in your frontend application!')
        ) 