"""
Management command to test file security implementations
"""

import os
import tempfile
from django.core.management.base import BaseCommand
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.exceptions import ValidationError
from core_config.file_security import EnhancedFileSecurityValidator, validate_file_security_enhanced
from core_config.malware_scanner import MalwareScanner, scan_file_for_malware


class Command(BaseCommand):
    help = 'Test file security implementations'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--test-type',
            type=str,
            choices=['all', 'validation', 'malware', 'integration'],
            default='all',
            help='Type of file security test to run'
        )
        
        parser.add_argument(
            '--create-samples',
            action='store_true',
            help='Create sample malicious files for testing'
        )
    
    def handle(self, *args, **options):
        test_type = options['test_type']
        create_samples = options['create_samples']
        
        self.stdout.write(
            self.style.SUCCESS(f'Running file security tests: {test_type}')
        )
        
        if create_samples:
            self.create_test_samples()
        
        if test_type in ['all', 'validation']:
            self.test_file_validation()
        
        if test_type in ['all', 'malware']:
            self.test_malware_scanner()
        
        if test_type in ['all', 'integration']:
            self.test_integration()
        
        self.stdout.write(
            self.style.SUCCESS('File security tests completed successfully!')
        )
    
    def create_test_samples(self):
        """Create sample files for testing"""
        self.stdout.write('Creating test sample files...')
        
        samples = {
            'valid_jpeg.jpg': b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00',
            'valid_png.png': b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a\x00\x00\x00\x0dIHDR\x00\x00\x00\x01',
            'valid_pdf.pdf': b'%PDF-1.4\n1 0 obj\n<<\n/Type /Catalog\n>>\nendobj\nxref\n%%EOF',
            'fake_jpeg.jpg': b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a',  # PNG header with JPG extension
            'executable.jpg': b'MZ\x90\x00\x03\x00\x00\x00\x04\x00',  # PE executable header
            'script_injection.jpg': b'\xff\xd8\xff\xe0<script>alert("xss")</script>',
            'php_webshell.jpg': b'\xff\xd8\xff\xe0<?php system($_GET["cmd"]); ?>',
            'sql_injection.txt': b"'; DROP TABLE users; --",
            'zip_bomb.jpg': b'PK\x03\x04\x14\x00\x00\x00\x08\x00',
            'polyglot.pdf': b'%PDF-1.4\n<html><script>alert("xss")</script></html>',
        }
        
        test_dir = os.path.join(tempfile.gettempdir(), 'file_security_tests')
        os.makedirs(test_dir, exist_ok=True)
        
        for filename, content in samples.items():
            filepath = os.path.join(test_dir, filename)
            with open(filepath, 'wb') as f:
                f.write(content)
            self.stdout.write(f'  Created: {filepath}')
        
        self.stdout.write(f'Test samples created in: {test_dir}')
    
    def test_file_validation(self):
        """Test file validation system"""
        self.stdout.write('Testing file validation system...')
        
        validator = EnhancedFileSecurityValidator()
        
        # Test valid files
        valid_files = [
            ('valid.jpg', b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00'),
            ('valid.png', b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a\x00\x00\x00\x0dIHDR\x00\x00\x00\x01'),
            ('valid.pdf', b'%PDF-1.4\n1 0 obj\n<<\n/Type /Catalog\n>>\nendobj\nxref\n%%EOF'),
        ]
        
        for filename, content in valid_files:
            test_file = SimpleUploadedFile(filename, content)
            try:
                result = validator.validate_file_comprehensive(test_file)
                if result['is_safe']:
                    self.stdout.write(
                        self.style.SUCCESS(f'  ✅ Valid file test passed: {filename}')
                    )
                else:
                    self.stdout.write(
                        self.style.WARNING(f'  ⚠️  Valid file has warnings: {filename}')
                    )
            except ValidationError as e:
                self.stdout.write(
                    self.style.ERROR(f'  ❌ Valid file test failed: {filename} - {str(e)}')
                )
        
        # Test malicious files
        malicious_files = [
            ('fake.jpg', b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a'),  # PNG with JPG extension
            ('executable.jpg', b'MZ\x90\x00\x03\x00\x00\x00\x04\x00'),  # Executable
            ('script.jpg', b'\xff\xd8\xff\xe0<script>alert("xss")</script>'),  # Script injection
            ('empty.jpg', b''),  # Empty file
            ('no_ext', b'\xff\xd8\xff\xe0'),  # No extension
            ('large.jpg', b'A' * (11 * 1024 * 1024)),  # Too large
        ]
        
        for filename, content in malicious_files:
            test_file = SimpleUploadedFile(filename, content)
            try:
                result = validator.validate_file_comprehensive(test_file)
                self.stdout.write(
                    self.style.ERROR(f'  ❌ Malicious file test failed: {filename} (should have been blocked)')
                )
            except ValidationError:
                self.stdout.write(
                    self.style.SUCCESS(f'  ✅ Malicious file blocked: {filename}')
                )
    
    def test_malware_scanner(self):
        """Test malware scanner"""
        self.stdout.write('Testing malware scanner...')
        
        scanner = MalwareScanner()
        
        # Test clean files
        clean_files = [
            ('clean.txt', b'This is a clean text file.'),
            ('clean.jpg', b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00'),
        ]
        
        for filename, content in clean_files:
            test_file = SimpleUploadedFile(filename, content)
            try:
                result = scanner.scan_file(test_file, filename)
                if result['is_clean']:
                    self.stdout.write(
                        self.style.SUCCESS(f'  ✅ Clean file scan passed: {filename}')
                    )
                else:
                    self.stdout.write(
                        self.style.WARNING(f'  ⚠️  Clean file has warnings: {filename}')
                    )
            except ValidationError as e:
                self.stdout.write(
                    self.style.ERROR(f'  ❌ Clean file scan failed: {filename} - {str(e)}')
                )
        
        # Test malicious files
        malicious_files = [
            ('executable.bin', b'MZ\x90\x00\x03\x00\x00\x00\x04\x00'),
            ('script.html', b'<script>alert("xss")</script>'),
            ('webshell.php', b'<?php system($_GET["cmd"]); ?>'),
            ('sql_injection.sql', b"'; DROP TABLE users; --"),
            ('polyglot.pdf', b'%PDF-1.4\n<html><script>alert("xss")</script></html>'),
        ]
        
        for filename, content in malicious_files:
            test_file = SimpleUploadedFile(filename, content)
            try:
                result = scanner.scan_file(test_file, filename)
                self.stdout.write(
                    self.style.ERROR(f'  ❌ Malware scan failed: {filename} (should have been detected)')
                )
            except ValidationError:
                self.stdout.write(
                    self.style.SUCCESS(f'  ✅ Malware detected: {filename}')
                )
        
        # Test scanner statistics
        stats = scanner.get_scan_statistics()
        self.stdout.write(f'  Scanner statistics: {stats}')
    
    def test_integration(self):
        """Test integration between validation and malware scanning"""
        self.stdout.write('Testing integration...')
        
        # Test Django field validation function
        test_cases = [
            ('valid.jpg', b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00', True),
            ('malicious.jpg', b'MZ\x90\x00\x03\x00\x00\x00\x04\x00', False),
            ('script.jpg', b'\xff\xd8\xff\xe0<script>alert("xss")</script>', False),
        ]
        
        for filename, content, should_pass in test_cases:
            test_file = SimpleUploadedFile(filename, content)
            try:
                result = validate_file_security_enhanced(test_file)
                if should_pass:
                    self.stdout.write(
                        self.style.SUCCESS(f'  ✅ Integration test passed: {filename}')
                    )
                else:
                    self.stdout.write(
                        self.style.ERROR(f'  ❌ Integration test failed: {filename} (should have been blocked)')
                    )
            except ValidationError:
                if not should_pass:
                    self.stdout.write(
                        self.style.SUCCESS(f'  ✅ Integration test passed: {filename} (correctly blocked)')
                    )
                else:
                    self.stdout.write(
                        self.style.ERROR(f'  ❌ Integration test failed: {filename} (should have passed)')
                    )
        
        # Test malware scanner function
        script_file = SimpleUploadedFile('test_script.html', b'<script>alert("test")</script>')
        try:
            result = scan_file_for_malware(script_file, 'test_script.html')
            self.stdout.write(
                self.style.ERROR('  ❌ Malware scanner integration failed (should have detected threat)')
            )
        except ValidationError:
            self.stdout.write(
                self.style.SUCCESS('  ✅ Malware scanner integration passed')
            )
    
    def test_performance(self):
        """Test performance of file security system"""
        self.stdout.write('Testing performance...')
        
        import time
        
        # Create test files of different sizes
        test_sizes = [1024, 10*1024, 100*1024, 1024*1024]  # 1KB, 10KB, 100KB, 1MB
        
        for size in test_sizes:
            content = b'A' * size
            test_file = SimpleUploadedFile(f'test_{size}.txt', content)
            
            start_time = time.time()
            try:
                validate_file_security_enhanced(test_file)
            except ValidationError:
                pass  # Expected for some test cases
            end_time = time.time()
            
            duration = (end_time - start_time) * 1000  # Convert to milliseconds
            self.stdout.write(f'  File size {size:,} bytes: {duration:.2f}ms')
            
            if duration > 1000:  # More than 1 second
                self.stdout.write(
                    self.style.WARNING(f'  ⚠️  Performance warning: {duration:.2f}ms for {size:,} bytes')
                )
    
    def cleanup_test_files(self):
        """Clean up test files"""
        test_dir = os.path.join(tempfile.gettempdir(), 'file_security_tests')
        if os.path.exists(test_dir):
            import shutil
            shutil.rmtree(test_dir)
            self.stdout.write(f'Cleaned up test directory: {test_dir}')