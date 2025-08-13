"""
Comprehensive test suite for enhanced file security validation
"""

import os
import io
import tempfile
from django.test import TestCase
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.exceptions import ValidationError
from core_config.file_security import EnhancedFileSecurityValidator, validate_file_security_enhanced
from core_config.malware_scanner import MalwareScanner, scan_file_for_malware


class TestEnhancedFileSecurityValidator(TestCase):
    """Test cases for EnhancedFileSecurityValidator"""
    
    def setUp(self):
        self.validator = EnhancedFileSecurityValidator()
    
    def create_test_file(self, filename: str, content: bytes, content_type: str = 'application/octet-stream'):
        """Helper to create test files"""
        return SimpleUploadedFile(
            name=filename,
            content=content,
            content_type=content_type
        )
    
    def test_valid_jpeg_file(self):
        """Test validation of valid JPEG file"""
        # JPEG header
        jpeg_content = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00\xff\xdb\x00C\x00'
        jpeg_content += b'\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t\x08\n\x0c\x14\r\x0c\x0b\x0b\x0c'
        jpeg_content += b'\x19\x12\x13\x0f\x14\x1d\x1a\x1f\x1e\x1d\x1a\x1c\x1c $.\' ",#\x1c\x1c(7),01444'
        jpeg_content += b'\x1f\'9=82<.342\xff\xc0\x00\x11\x08\x00\x01\x00\x01\x01\x01\x11\x00\x02\x11\x01\x03\x11\x01'
        
        test_file = self.create_test_file('test.jpg', jpeg_content, 'image/jpeg')
        
        try:
            result = self.validator.validate_file_comprehensive(test_file)
            self.assertTrue(result['is_safe'])
            self.assertEqual(result['extension'], '.jpg')
            self.assertIn('basic_info', result['checks_passed'])
            self.assertIn('extension', result['checks_passed'])
            self.assertIn('file_signature', result['checks_passed'])
        except ValidationError:
            self.fail("Valid JPEG file should not raise ValidationError")
    
    def test_valid_png_file(self):
        """Test validation of valid PNG file"""
        # PNG header
        png_content = b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a\x00\x00\x00\x0dIHDR\x00\x00\x00\x01\x00\x00\x00\x01'
        png_content += b'\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc```\x00\x00\x00\x04\x00\x01'
        png_content += b'\xdd\x8d\xb4\x1c\x00\x00\x00\x00IEND\xaeB`\x82'
        
        test_file = self.create_test_file('test.png', png_content, 'image/png')
        
        try:
            result = self.validator.validate_file_comprehensive(test_file)
            self.assertTrue(result['is_safe'])
            self.assertEqual(result['extension'], '.png')
        except ValidationError:
            self.fail("Valid PNG file should not raise ValidationError")
    
    def test_valid_pdf_file(self):
        """Test validation of valid PDF file"""
        # Minimal PDF content
        pdf_content = b'%PDF-1.4\n1 0 obj\n<<\n/Type /Catalog\n/Pages 2 0 R\n>>\nendobj\n'
        pdf_content += b'2 0 obj\n<<\n/Type /Pages\n/Kids [3 0 R]\n/Count 1\n>>\nendobj\n'
        pdf_content += b'3 0 obj\n<<\n/Type /Page\n/Parent 2 0 R\n/MediaBox [0 0 612 792]\n>>\nendobj\n'
        pdf_content += b'xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000074 00000 n \n'
        pdf_content += b'0000000120 00000 n \ntrailer\n<<\n/Size 4\n/Root 1 0 R\n>>\nstartxref\n202\n%%EOF'
        
        test_file = self.create_test_file('test.pdf', pdf_content, 'application/pdf')
        
        try:
            result = self.validator.validate_file_comprehensive(test_file)
            self.assertTrue(result['is_safe'])
            self.assertEqual(result['extension'], '.pdf')
        except ValidationError:
            self.fail("Valid PDF file should not raise ValidationError")
    
    def test_invalid_extension(self):
        """Test rejection of invalid file extensions"""
        test_file = self.create_test_file('malicious.exe', b'MZ\x90\x00', 'application/octet-stream')
        
        with self.assertRaises(ValidationError) as context:
            self.validator.validate_file_comprehensive(test_file)
        
        self.assertIn('not allowed', str(context.exception))
    
    def test_file_size_limit(self):
        """Test file size validation"""
        # Create a file larger than the limit
        large_content = b'A' * (11 * 1024 * 1024)  # 11MB
        test_file = self.create_test_file('large.jpg', large_content, 'image/jpeg')
        
        with self.assertRaises(ValidationError) as context:
            self.validator.validate_file_comprehensive(test_file)
        
        self.assertIn('exceeds maximum allowed size', str(context.exception))
    
    def test_signature_mismatch(self):
        """Test detection of signature mismatch"""
        # PNG content with JPEG extension
        png_content = b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a'
        test_file = self.create_test_file('fake.jpg', png_content, 'image/jpeg')
        
        with self.assertRaises(ValidationError) as context:
            self.validator.validate_file_comprehensive(test_file)
        
        self.assertIn('does not match extension', str(context.exception))
    
    def test_executable_detection(self):
        """Test detection of executable files"""
        # PE executable header
        exe_content = b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'
        test_file = self.create_test_file('malware.jpg', exe_content, 'image/jpeg')
        
        with self.assertRaises(ValidationError) as context:
            self.validator.validate_file_comprehensive(test_file)
        
        self.assertIn('Dangerous file signature', str(context.exception))
    
    def test_zip_file_detection(self):
        """Test detection of ZIP files"""
        # ZIP file header
        zip_content = b'PK\x03\x04\x14\x00\x00\x00\x08\x00'
        test_file = self.create_test_file('archive.jpg', zip_content, 'image/jpeg')
        
        with self.assertRaises(ValidationError) as context:
            self.validator.validate_file_comprehensive(test_file)
        
        self.assertIn('ZIP archives are not allowed', str(context.exception))
    
    def test_suspicious_filename(self):
        """Test detection of suspicious filenames"""
        suspicious_names = [
            '../../../etc/passwd',
            'file<script>.jpg',
            'test\x00.jpg',
            'CON.jpg',
            'PRN.png',
        ]
        
        for filename in suspicious_names:
            test_file = self.create_test_file(filename, b'\xff\xd8\xff\xe0', 'image/jpeg')
            
            with self.assertRaises(ValidationError) as context:
                self.validator.validate_file_comprehensive(test_file)
            
            self.assertIn('Suspicious filename', str(context.exception))
    
    def test_double_extension(self):
        """Test detection of double extensions"""
        test_file = self.create_test_file('image.jpg.exe', b'\xff\xd8\xff\xe0', 'image/jpeg')
        
        try:
            result = self.validator.validate_file_comprehensive(test_file)
            # Should generate a warning but not fail
            self.assertIn('Multiple extensions detected', ' '.join(result['warnings']))
        except ValidationError:
            # This is also acceptable behavior
            pass
    
    def test_empty_file(self):
        """Test rejection of empty files"""
        test_file = self.create_test_file('empty.jpg', b'', 'image/jpeg')
        
        with self.assertRaises(ValidationError) as context:
            self.validator.validate_file_comprehensive(test_file)
        
        self.assertIn('empty', str(context.exception))
    
    def test_no_extension(self):
        """Test rejection of files without extensions"""
        test_file = self.create_test_file('noextension', b'\xff\xd8\xff\xe0', 'image/jpeg')
        
        with self.assertRaises(ValidationError) as context:
            self.validator.validate_file_comprehensive(test_file)
        
        self.assertIn('must have an extension', str(context.exception))


class TestMalwareScanner(TestCase):
    """Test cases for MalwareScanner"""
    
    def setUp(self):
        self.scanner = MalwareScanner()
    
    def create_test_file(self, filename: str, content: bytes):
        """Helper to create test files"""
        return SimpleUploadedFile(name=filename, content=content)
    
    def test_clean_file_scan(self):
        """Test scanning of clean file"""
        clean_content = b'This is a clean text file with normal content.'
        test_file = self.create_test_file('clean.txt', clean_content)
        
        try:
            result = self.scanner.scan_file(test_file, 'clean.txt')
            self.assertTrue(result['is_clean'])
            self.assertEqual(len(result['threats_detected']), 0)
        except ValidationError:
            self.fail("Clean file should not raise ValidationError")
    
    def test_executable_detection(self):
        """Test detection of executable files"""
        exe_content = b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'
        test_file = self.create_test_file('malware.exe', exe_content)
        
        with self.assertRaises(ValidationError) as context:
            self.scanner.scan_file(test_file, 'malware.exe')
        
        self.assertIn('malicious content', str(context.exception))
    
    def test_script_detection(self):
        """Test detection of script content"""
        script_content = b'<script>alert("xss")</script>'
        test_file = self.create_test_file('script.html', script_content)
        
        with self.assertRaises(ValidationError) as context:
            self.scanner.scan_file(test_file, 'script.html')
        
        self.assertIn('malicious content', str(context.exception))
    
    def test_php_detection(self):
        """Test detection of PHP code"""
        php_content = b'<?php system($_GET["cmd"]); ?>'
        test_file = self.create_test_file('webshell.php', php_content)
        
        with self.assertRaises(ValidationError) as context:
            self.scanner.scan_file(test_file, 'webshell.php')
        
        self.assertIn('malicious content', str(context.exception))
    
    def test_sql_injection_detection(self):
        """Test detection of SQL injection patterns"""
        sql_content = b"'; DROP TABLE users; --"
        test_file = self.create_test_file('injection.sql', sql_content)
        
        with self.assertRaises(ValidationError) as context:
            self.scanner.scan_file(test_file, 'injection.sql')
        
        self.assertIn('malicious content', str(context.exception))
    
    def test_entropy_analysis(self):
        """Test entropy analysis for packed content"""
        # High entropy content (random bytes)
        import random
        high_entropy_content = bytes([random.randint(0, 255) for _ in range(1000)])
        test_file = self.create_test_file('packed.bin', high_entropy_content)
        
        try:
            result = self.scanner.scan_file(test_file, 'packed.bin')
            # Should either detect as threat or generate warning
            self.assertTrue(
                not result['is_clean'] or len(result['warnings']) > 0
            )
        except ValidationError:
            # High entropy detection is also acceptable
            pass
    
    def test_polyglot_detection(self):
        """Test detection of polyglot files"""
        # PDF with HTML content
        polyglot_content = b'%PDF-1.4\n<html><script>alert("xss")</script></html>'
        test_file = self.create_test_file('polyglot.pdf', polyglot_content)
        
        with self.assertRaises(ValidationError) as context:
            self.scanner.scan_file(test_file, 'polyglot.pdf')
        
        self.assertIn('malicious content', str(context.exception))
    
    def test_hash_based_detection(self):
        """Test hash-based malware detection"""
        # Add a test hash to the scanner
        test_content = b'test malware content'
        import hashlib
        test_hash = hashlib.md5(test_content).hexdigest()
        
        self.scanner.update_malware_database({test_hash: 'Test.Malware'})
        
        test_file = self.create_test_file('malware.bin', test_content)
        
        with self.assertRaises(ValidationError) as context:
            self.scanner.scan_file(test_file, 'malware.bin')
        
        self.assertIn('Test.Malware', str(context.exception))
    
    def test_scan_statistics(self):
        """Test scan statistics functionality"""
        # Perform some scans
        clean_file = self.create_test_file('clean.txt', b'clean content')
        
        try:
            self.scanner.scan_file(clean_file, 'clean.txt')
        except ValidationError:
            pass
        
        stats = self.scanner.get_scan_statistics()
        self.assertIsInstance(stats, dict)
        self.assertIn('total_scans', stats)
        self.assertIn('clean_files', stats)
        self.assertIn('infected_files', stats)


class TestFileSecurityIntegration(TestCase):
    """Integration tests for file security system"""
    
    def test_django_field_validation(self):
        """Test Django model field validation"""
        # Valid JPEG
        jpeg_content = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00'
        valid_file = SimpleUploadedFile('test.jpg', jpeg_content, 'image/jpeg')
        
        try:
            result = validate_file_security_enhanced(valid_file)
            self.assertTrue(result)
        except ValidationError:
            self.fail("Valid file should not raise ValidationError")
        
        # Invalid executable
        exe_content = b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'
        invalid_file = SimpleUploadedFile('malware.jpg', exe_content, 'image/jpeg')
        
        with self.assertRaises(ValidationError):
            validate_file_security_enhanced(invalid_file)
    
    def test_malware_scanner_integration(self):
        """Test integration with malware scanner"""
        script_content = b'<script>alert("xss")</script>'
        malicious_file = SimpleUploadedFile('script.jpg', script_content, 'image/jpeg')
        
        with self.assertRaises(ValidationError) as context:
            scan_result = scan_file_for_malware(malicious_file, 'script.jpg')
        
        self.assertIn('malicious content', str(context.exception))
    
    def test_comprehensive_security_check(self):
        """Test comprehensive security validation"""
        # Create a file that should trigger multiple security checks
        malicious_content = b'\xff\xd8\xff\xe0'  # JPEG header
        malicious_content += b'<script>eval(atob("'  # XSS + obfuscation
        malicious_content += b'YWxlcnQoImhhY2tlZCIp'  # base64 encoded alert("hacked")
        malicious_content += b'"))</script>'
        malicious_content += b'<?php system($_GET["cmd"]); ?>'  # PHP backdoor
        
        malicious_file = SimpleUploadedFile('malicious.jpg', malicious_content, 'image/jpeg')
        
        with self.assertRaises(ValidationError) as context:
            validate_file_security_enhanced(malicious_file)
        
        error_message = str(context.exception)
        # Should detect multiple threats
        self.assertTrue(
            'malicious' in error_message.lower() or 
            'suspicious' in error_message.lower()
        )


if __name__ == '__main__':
    # Run tests
    import django
    from django.conf import settings
    from django.test.utils import get_runner
    
    if not settings.configured:
        settings.configure(
            DEBUG=True,
            DATABASES={
                'default': {
                    'ENGINE': 'django.db.backends.sqlite3',
                    'NAME': ':memory:',
                }
            },
            INSTALLED_APPS=[
                'django.contrib.auth',
                'django.contrib.contenttypes',
                'core_config',
            ],
            SECRET_KEY='test-secret-key',
            USE_TZ=True,
        )
    
    django.setup()
    
    TestRunner = get_runner(settings)
    test_runner = TestRunner()
    failures = test_runner.run_tests(['__main__'])
    
    if failures:
        exit(1)