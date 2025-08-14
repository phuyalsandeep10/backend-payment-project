"""
Enhanced File Security Validator
Comprehensive file validation with bypass prevention and malware detection
Enhanced for security-performance-overhaul task 1.1.2
"""

import os
import re
import hashlib
import logging
import mimetypes
import tempfile
import subprocess
from typing import List, Dict, Optional, Tuple, Union
from django.core.exceptions import ValidationError
from django.conf import settings
from PIL import Image
import zipfile
import io
import json
from datetime import datetime, timedelta

# Security logger
security_logger = logging.getLogger('security')

# Try to import magic, but fall back gracefully if not available
try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False
    security_logger.warning("python-magic not available. File type detection will be limited.")

class EnhancedFileSecurityValidator:
    """
    Enhanced file security validator with comprehensive threat detection
    and bypass prevention capabilities
    """
    
    # Maximum file sizes by type (in bytes)
    MAX_FILE_SIZES = {
        'image': 10 * 1024 * 1024,  # 10MB for images
        'pdf': 25 * 1024 * 1024,    # 25MB for PDFs
        'document': 50 * 1024 * 1024, # 50MB for documents
        'default': 5 * 1024 * 1024   # 5MB default
    }
    
    # Rate limiting for file uploads (per IP per hour)
    UPLOAD_RATE_LIMITS = {
        'max_files_per_hour': 100,
        'max_total_size_per_hour': 500 * 1024 * 1024,  # 500MB
        'max_failed_attempts_per_hour': 10
    }
    
    # Allowed file extensions and their categories
    ALLOWED_EXTENSIONS = {
        # Images
        '.jpg': 'image',
        '.jpeg': 'image', 
        '.png': 'image',
        '.gif': 'image',
        '.webp': 'image',
        '.bmp': 'image',
        '.tiff': 'image',
        '.tif': 'image',
        
        # Documents
        '.pdf': 'pdf',
        '.doc': 'document',
        '.docx': 'document',
        '.xls': 'document',
        '.xlsx': 'document',
        '.ppt': 'document',
        '.pptx': 'document',
        '.txt': 'document',
        '.rtf': 'document',
        '.csv': 'document',
    }
    
    # MIME type mappings for validation
    MIME_TYPE_MAPPINGS = {
        '.jpg': ['image/jpeg'],
        '.jpeg': ['image/jpeg'],
        '.png': ['image/png'],
        '.gif': ['image/gif'],
        '.webp': ['image/webp'],
        '.bmp': ['image/bmp', 'image/x-ms-bmp'],
        '.tiff': ['image/tiff'],
        '.tif': ['image/tiff'],
        '.pdf': ['application/pdf'],
        '.doc': ['application/msword'],
        '.docx': ['application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
        '.xls': ['application/vnd.ms-excel'],
        '.xlsx': ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
        '.ppt': ['application/vnd.ms-powerpoint'],
        '.pptx': ['application/vnd.openxmlformats-officedocument.presentationml.presentation'],
        '.txt': ['text/plain'],
        '.rtf': ['application/rtf', 'text/rtf'],
        '.csv': ['text/csv', 'application/csv'],
    }
    
    # File magic numbers (signatures) for validation
    FILE_SIGNATURES = {
        '.jpg': [b'\xff\xd8\xff\xe0', b'\xff\xd8\xff\xe1', b'\xff\xd8\xff\xdb'],
        '.jpeg': [b'\xff\xd8\xff\xe0', b'\xff\xd8\xff\xe1', b'\xff\xd8\xff\xdb'],
        '.png': [b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a'],
        '.gif': [b'GIF87a', b'GIF89a'],
        '.webp': [b'RIFF', b'WEBP'],
        '.bmp': [b'BM'],
        '.tiff': [b'II*\x00', b'MM\x00*'],
        '.tif': [b'II*\x00', b'MM\x00*'],
        '.pdf': [b'%PDF-'],
        '.doc': [b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'],
        '.docx': [b'PK\x03\x04'],
        '.xls': [b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'],
        '.xlsx': [b'PK\x03\x04'],
        '.ppt': [b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'],
        '.pptx': [b'PK\x03\x04'],
        '.txt': [],  # Text files don't have specific signatures
        '.rtf': [b'{\\rtf'],
        '.csv': [],  # CSV files don't have specific signatures
    }
    
    # Dangerous file signatures to block
    DANGEROUS_SIGNATURES = [
        b'MZ',  # PE executable
        b'\x7fELF',  # ELF executable
        b'\xfe\xed\xfa\xce',  # Mach-O executable (32-bit)
        b'\xfe\xed\xfa\xcf',  # Mach-O executable (64-bit)
        b'\xca\xfe\xba\xbe',  # Java class file
        b'PK\x03\x04\x14\x00\x06\x00',  # Encrypted ZIP
        b'\x50\x4b\x03\x04',  # ZIP file (check content)
        b'\x1f\x8b\x08',  # GZIP
        b'BZh',  # BZIP2
        b'\xfd7zXZ\x00',  # XZ compressed
        b'\x37\x7a\xbc\xaf\x27\x1c',  # 7-Zip
        b'Rar!',  # RAR archive
    ]
    
    # Enhanced suspicious content patterns with bypass prevention
    SUSPICIOUS_PATTERNS = [
        # Script patterns (including obfuscated variants)
        rb'<script[^>]*>',
        rb'<SCRIPT[^>]*>',  # Case variations
        rb'<ScRiPt[^>]*>',
        rb'<\s*script[^>]*>',  # Whitespace variations
        rb'javascript:',
        rb'JAVASCRIPT:',
        rb'vbscript:',
        rb'VBSCRIPT:',
        rb'data:text/html',
        rb'data:application/javascript',
        rb'data:text/javascript',
        
        # Executable patterns
        rb'exec\s*\(',
        rb'eval\s*\(',
        rb'system\s*\(',
        rb'shell_exec\s*\(',
        rb'passthru\s*\(',
        rb'proc_open\s*\(',
        rb'popen\s*\(',
        rb'file_get_contents\s*\(',
        rb'file_put_contents\s*\(',
        rb'fopen\s*\(',
        rb'fwrite\s*\(',
        
        # PHP patterns (including obfuscated)
        rb'<\?php',
        rb'<\?PHP',
        rb'<\?\s*php',
        rb'<\?=',
        rb'<%',
        rb'<\s*\?',
        rb'\$_GET',
        rb'\$_POST',
        rb'\$_REQUEST',
        rb'\$_COOKIE',
        rb'\$_SESSION',
        rb'\$_SERVER',
        rb'base64_decode\s*\(',
        rb'gzinflate\s*\(',
        rb'str_rot13\s*\(',
        rb'gzuncompress\s*\(',
        
        # SQL patterns
        rb'DROP\s+TABLE',
        rb'DELETE\s+FROM',
        rb'INSERT\s+INTO',
        rb'UPDATE\s+SET',
        rb'UNION\s+SELECT',
        rb'SELECT\s+.*\s+FROM',
        rb'CREATE\s+TABLE',
        rb'ALTER\s+TABLE',
        rb'TRUNCATE\s+TABLE',
        
        # Command injection patterns
        rb';\s*rm\s+-rf',
        rb';\s*cat\s+/etc/passwd',
        rb';\s*wget\s+',
        rb';\s*curl\s+',
        rb';\s*nc\s+',
        rb';\s*netcat\s+',
        rb';\s*bash\s+',
        rb';\s*sh\s+',
        rb';\s*python\s+',
        rb';\s*perl\s+',
        rb';\s*ruby\s+',
        rb';\s*node\s+',
        
        # Bypass attempt patterns
        rb'null\x00',  # Null byte injection
        rb'%00',  # URL encoded null byte
        rb'\.\./',  # Path traversal
        rb'\.\.\\',  # Windows path traversal
        rb'%2e%2e%2f',  # URL encoded path traversal
        rb'%2e%2e%5c',  # URL encoded Windows path traversal
        rb'..%2f',  # Mixed encoding
        rb'..%5c',  # Mixed encoding
        
        # Polyglot file patterns
        rb'%PDF-.*<html',  # PDF with HTML
        rb'\xff\xd8\xff.*<script',  # JPEG with script
        rb'\x89PNG.*<\?php',  # PNG with PHP
        rb'GIF8.*<script',  # GIF with script
        
        # Archive bomb patterns
        rb'PK\x03\x04.*PK\x03\x04.*PK\x03\x04',  # Multiple ZIP headers
        rb'BZh[0-9]1AY&SY.*BZh[0-9]1AY&SY',  # Multiple BZIP2 headers
        
        # Steganography indicators
        rb'-----BEGIN PGP',  # PGP encrypted content
        rb'-----BEGIN CERTIFICATE',  # Certificate content
        rb'-----BEGIN PRIVATE KEY',  # Private key content
        rb'ssh-rsa\s+[A-Za-z0-9+/=]+',  # SSH public key
        rb'ssh-dss\s+[A-Za-z0-9+/=]+',  # SSH DSA key
    ]
    
    # File extension bypass patterns
    BYPASS_EXTENSIONS = [
        # Double extensions
        r'\.php\.',
        r'\.asp\.',
        r'\.jsp\.',
        r'\.exe\.',
        r'\.bat\.',
        r'\.cmd\.',
        r'\.scr\.',
        r'\.com\.',
        r'\.pif\.',
        
        # Null byte injection
        r'\.php%00',
        r'\.asp%00',
        r'\.jsp%00',
        r'\x00',
        
        # Case variations
        r'\.PHP$',
        r'\.ASP$',
        r'\.JSP$',
        r'\.EXE$',
        
        # Unicode variations
        r'\.ph\u0070',  # Unicode 'p'
        r'\.as\u0070',  # Unicode 'p'
        
        # Alternative extensions
        r'\.phtml$',
        r'\.php3$',
        r'\.php4$',
        r'\.php5$',
        r'\.php7$',
        r'\.phps$',
        r'\.pht$',
        r'\.phar$',
        r'\.inc$',
        r'\.aspx$',
        r'\.ashx$',
        r'\.asmx$',
        r'\.cfm$',
        r'\.cgi$',
        r'\.pl$',
        r'\.py$',
        r'\.rb$',
        r'\.sh$',
        r'\.bash$',
        r'\.zsh$',
        r'\.fish$',
    ]
    
    def __init__(self, allowed_extensions: Optional[List[str]] = None, 
                 enable_rate_limiting: bool = True):
        """
        Initialize the validator
        
        Args:
            allowed_extensions: List of allowed extensions (overrides default)
            enable_rate_limiting: Enable rate limiting for uploads
        """
        if allowed_extensions:
            self.allowed_extensions = {ext.lower(): 'custom' for ext in allowed_extensions}
        else:
            self.allowed_extensions = self.ALLOWED_EXTENSIONS
        
        self.enable_rate_limiting = enable_rate_limiting
        self.bypass_patterns = [re.compile(pattern, re.IGNORECASE) 
                               for pattern in self.BYPASS_EXTENSIONS]
        
        # Initialize quarantine directory
        self.quarantine_dir = getattr(settings, 'FILE_QUARANTINE_DIR', 
                                    os.path.join(settings.MEDIA_ROOT, 'quarantine'))
        os.makedirs(self.quarantine_dir, exist_ok=True)
    
    def validate_file_comprehensive(self, file_obj, client_ip: str = None, 
                                  user_id: str = None) -> Dict[str, any]:
        """
        Comprehensive file validation with detailed results and bypass prevention
        
        Args:
            file_obj: Django UploadedFile object
            client_ip: Client IP address for rate limiting
            user_id: User ID for tracking
            
        Returns:
            Dict with validation results and metadata
            
        Raises:
            ValidationError: If validation fails
        """
        validation_result = {
            'filename': file_obj.name,
            'size': file_obj.size,
            'extension': None,
            'mime_type': None,
            'file_hash': None,
            'is_safe': False,
            'warnings': [],
            'checks_passed': [],
            'bypass_attempts': [],
            'quarantined': False,
            'scan_timestamp': datetime.now().isoformat()
        }
        
        try:
            # Step 0: Rate limiting check
            if self.enable_rate_limiting and client_ip:
                self._check_rate_limits(client_ip, file_obj.size, validation_result)
            
            # Step 1: Basic file information validation
            self._validate_basic_info(file_obj, validation_result)
            
            # Step 2: Bypass attempt detection
            self._detect_bypass_attempts(file_obj, validation_result)
            
            # Step 3: File extension validation (enhanced)
            self._validate_extension_enhanced(file_obj, validation_result)
            
            # Step 4: File size validation
            self._validate_file_size(file_obj, validation_result)
            
            # Step 5: File signature validation (enhanced)
            self._validate_file_signature_enhanced(file_obj, validation_result)
            
            # Step 6: MIME type validation (enhanced)
            self._validate_mime_type_enhanced(file_obj, validation_result)
            
            # Step 7: Content analysis (enhanced)
            self._analyze_file_content_enhanced(file_obj, validation_result)
            
            # Step 8: Malware signature detection
            self._detect_malware_signatures(file_obj, validation_result)
            
            # Step 9: Type-specific validation
            self._validate_by_type(file_obj, validation_result)
            
            # Step 10: Polyglot file detection
            self._detect_polyglot_files(file_obj, validation_result)
            
            # Step 11: Archive bomb detection
            self._detect_archive_bombs(file_obj, validation_result)
            
            # Step 12: Steganography detection
            self._detect_steganography(file_obj, validation_result)
            
            # Step 13: Generate file hash for integrity
            validation_result['file_hash'] = self._generate_file_hash(file_obj)
            
            # Step 14: Final security assessment
            validation_result['is_safe'] = (
                len(validation_result['warnings']) == 0 and 
                len(validation_result['bypass_attempts']) == 0
            )
            
            # Log successful validation
            security_logger.info(
                f"File validation successful: {file_obj.name} "
                f"({validation_result['size']} bytes, {validation_result['extension']})"
            )
            
            return validation_result
            
        except ValidationError as e:
            # Log validation failure
            security_logger.error(
                f"File validation failed: {file_obj.name} - {str(e)}"
            )
            raise
        
        except Exception as e:
            # Log unexpected error
            security_logger.error(
                f"Unexpected error during file validation: {file_obj.name} - {str(e)}"
            )
            raise ValidationError(f"File validation error: {str(e)}")
    
    def _validate_basic_info(self, file_obj, result: Dict):
        """Validate basic file information"""
        if not file_obj.name:
            raise ValidationError("File name is required")
        
        if file_obj.size <= 0:
            raise ValidationError("File is empty")
        
        # Check for suspicious filename patterns
        suspicious_name_patterns = [
            r'\.\./',  # Path traversal
            r'[<>:"|?*]',  # Invalid filename characters
            r'^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|$)',  # Windows reserved names
            r'\x00',  # Null bytes
        ]
        
        for pattern in suspicious_name_patterns:
            if re.search(pattern, file_obj.name, re.IGNORECASE):
                raise ValidationError(f"Suspicious filename pattern detected: {file_obj.name}")
        
        result['checks_passed'].append('basic_info')
    
    def _check_rate_limits(self, client_ip: str, file_size: int, result: Dict):
        """Check upload rate limits to prevent abuse"""
        try:
            import redis
            from django.conf import settings
            
            # Connect to Redis
            redis_client = redis.Redis(
                host=getattr(settings, 'REDIS_HOST', 'localhost'),
                port=getattr(settings, 'REDIS_PORT', 6379),
                db=getattr(settings, 'REDIS_DB', 0)
            )
            
            current_hour = datetime.now().strftime('%Y%m%d%H')
            
            # Keys for tracking
            files_key = f"upload_files:{client_ip}:{current_hour}"
            size_key = f"upload_size:{client_ip}:{current_hour}"
            failed_key = f"upload_failed:{client_ip}:{current_hour}"
            
            # Get current counts
            files_count = int(redis_client.get(files_key) or 0)
            total_size = int(redis_client.get(size_key) or 0)
            failed_count = int(redis_client.get(failed_key) or 0)
            
            # Check limits
            if files_count >= self.UPLOAD_RATE_LIMITS['max_files_per_hour']:
                raise ValidationError(
                    f"Upload rate limit exceeded: {files_count} files uploaded this hour"
                )
            
            if total_size + file_size > self.UPLOAD_RATE_LIMITS['max_total_size_per_hour']:
                raise ValidationError(
                    f"Upload size limit exceeded: {total_size + file_size} bytes this hour"
                )
            
            if failed_count >= self.UPLOAD_RATE_LIMITS['max_failed_attempts_per_hour']:
                raise ValidationError(
                    f"Too many failed upload attempts: {failed_count} this hour"
                )
            
            # Update counters
            redis_client.incr(files_key)
            redis_client.expire(files_key, 3600)  # 1 hour
            redis_client.incrby(size_key, file_size)
            redis_client.expire(size_key, 3600)
            
            result['checks_passed'].append('rate_limiting')
            
        except redis.RedisError as e:
            security_logger.warning(f"Rate limiting check failed: {str(e)}")
            # Continue without rate limiting if Redis is unavailable
            pass
        except ValidationError:
            # Re-raise rate limit violations
            raise
    
    def _detect_bypass_attempts(self, file_obj, result: Dict):
        """Detect various bypass attempts"""
        filename = file_obj.name.lower()
        
        # Check for extension bypass patterns
        for pattern in self.bypass_patterns:
            if pattern.search(filename):
                result['bypass_attempts'].append(f"Extension bypass pattern: {pattern.pattern}")
        
        # Check for null byte injection
        if '\x00' in file_obj.name or '%00' in file_obj.name:
            result['bypass_attempts'].append("Null byte injection in filename")
        
        # Check for Unicode bypass attempts
        try:
            normalized = file_obj.name.encode('ascii', 'ignore').decode('ascii')
            if normalized != file_obj.name:
                result['bypass_attempts'].append("Non-ASCII characters in filename")
        except Exception:
            result['bypass_attempts'].append("Invalid filename encoding")
        
        # Check for excessive filename length
        if len(file_obj.name) > 255:
            result['bypass_attempts'].append("Excessively long filename")
        
        # Check for hidden file indicators
        if file_obj.name.startswith('.') and len(file_obj.name) > 1:
            result['warnings'].append("Hidden file detected")
        
        result['checks_passed'].append('bypass_detection')
    
    def _validate_extension(self, file_obj, result: Dict):
        """Validate file extension"""
        filename = file_obj.name.lower()
        ext = os.path.splitext(filename)[1]
        
        if not ext:
            raise ValidationError("File must have an extension")
        
        if ext not in self.allowed_extensions:
            allowed_list = ', '.join(self.allowed_extensions.keys())
            raise ValidationError(
                f"File extension '{ext}' not allowed. "
                f"Allowed extensions: {allowed_list}"
            )
        
        # Check for double extensions (e.g., .jpg.exe)
        name_parts = filename.split('.')
        if len(name_parts) > 2:
            for part in name_parts[1:-1]:  # Check middle parts
                if f'.{part}' in self.allowed_extensions:
                    result['warnings'].append(f"Multiple extensions detected: {filename}")
                    break
        
        result['extension'] = ext
        result['checks_passed'].append('extension')
    
    def _validate_extension_enhanced(self, file_obj, result: Dict):
        """Enhanced extension validation with bypass prevention"""
        filename = file_obj.name.lower()
        
        # Get all extensions (handle multiple dots)
        parts = filename.split('.')
        if len(parts) < 2:
            raise ValidationError("File must have an extension")
        
        # Check each extension part
        extensions = [f'.{part}' for part in parts[1:]]
        final_ext = extensions[-1]
        
        # Validate final extension
        if final_ext not in self.allowed_extensions:
            allowed_list = ', '.join(self.allowed_extensions.keys())
            raise ValidationError(
                f"File extension '{final_ext}' not allowed. "
                f"Allowed extensions: {allowed_list}"
            )
        
        # Check for dangerous intermediate extensions
        dangerous_intermediate = [
            '.php', '.asp', '.jsp', '.exe', '.bat', '.cmd', '.scr', 
            '.com', '.pif', '.vbs', '.js', '.jar', '.py', '.pl', 
            '.rb', '.sh', '.bash', '.cgi', '.htaccess'
        ]
        
        for ext in extensions[:-1]:  # All except the last one
            if ext in dangerous_intermediate:
                result['bypass_attempts'].append(
                    f"Dangerous intermediate extension: {ext}"
                )
        
        # Check for case variation bypass attempts
        original_ext = os.path.splitext(file_obj.name)[1]
        if original_ext != original_ext.lower():
            result['warnings'].append(f"Mixed case extension: {original_ext}")
        
        # Check for whitespace in extension
        if ' ' in original_ext or '\t' in original_ext:
            result['bypass_attempts'].append("Whitespace in file extension")
        
        result['extension'] = final_ext
        result['checks_passed'].append('extension_enhanced')
    
    def _validate_file_size(self, file_obj, result: Dict):
        """Validate file size"""
        ext = result['extension']
        file_category = self.allowed_extensions.get(ext, 'default')
        max_size = self.MAX_FILE_SIZES.get(file_category, self.MAX_FILE_SIZES['default'])
        
        if file_obj.size > max_size:
            raise ValidationError(
                f"File size ({file_obj.size:,} bytes) exceeds maximum allowed "
                f"size for {file_category} files ({max_size:,} bytes)"
            )
        
        result['checks_passed'].append('file_size')
    
    def _validate_file_signature(self, file_obj, result: Dict):
        """Validate file signature (magic numbers)"""
        ext = result['extension']
        expected_signatures = self.FILE_SIGNATURES.get(ext, [])
        
        if not expected_signatures:
            # No signature validation for this file type
            result['checks_passed'].append('file_signature')
            return
        
        # Read file header
        file_obj.seek(0)
        header = file_obj.read(32)  # Read first 32 bytes
        file_obj.seek(0)
        
        # Check if header matches expected signatures
        signature_match = False
        for signature in expected_signatures:
            if header.startswith(signature):
                signature_match = True
                break
        
        if not signature_match:
            raise ValidationError(
                f"File signature does not match extension '{ext}'. "
                f"File may be corrupted or disguised."
            )
        
        result['checks_passed'].append('file_signature')
    
    def _validate_file_signature_enhanced(self, file_obj, result: Dict):
        """Enhanced file signature validation with deeper analysis"""
        ext = result['extension']
        expected_signatures = self.FILE_SIGNATURES.get(ext, [])
        
        if not expected_signatures:
            result['checks_passed'].append('file_signature_enhanced')
            return
        
        # Read more of the file header for better detection
        file_obj.seek(0)
        header = file_obj.read(1024)  # Read first 1KB instead of 32 bytes
        file_obj.seek(0)
        
        # Check primary signature
        signature_match = False
        matched_signature = None
        
        for signature in expected_signatures:
            if header.startswith(signature):
                signature_match = True
                matched_signature = signature
                break
        
        if not signature_match:
            raise ValidationError(
                f"Enhanced signature validation failed for extension '{ext}'. "
                f"File may be corrupted or disguised."
            )
        
        # Additional signature validation for specific file types
        if ext in ['.jpg', '.jpeg']:
            # JPEG files should end with FFD9
            file_obj.seek(-2, 2)  # Seek to last 2 bytes
            end_marker = file_obj.read(2)
            file_obj.seek(0)
            if end_marker != b'\xff\xd9':
                result['warnings'].append("JPEG file missing proper end marker")
        
        elif ext == '.png':
            # PNG files should have IHDR chunk after signature
            if b'IHDR' not in header[:50]:
                raise ValidationError("PNG file missing IHDR chunk")
            # PNG files should end with IEND
            file_obj.seek(-12, 2)
            end_chunk = file_obj.read(12)
            file_obj.seek(0)
            if b'IEND' not in end_chunk:
                result['warnings'].append("PNG file missing IEND chunk")
        
        elif ext == '.pdf':
            # Check PDF structure more thoroughly
            if b'%%EOF' not in header and file_obj.size > 1024:
                # Check end of file for EOF marker
                file_obj.seek(-1024, 2)
                tail = file_obj.read(1024)
                file_obj.seek(0)
                if b'%%EOF' not in tail:
                    result['warnings'].append("PDF file missing EOF marker")
        
        elif ext == '.gif':
            # GIF files should have proper trailer
            file_obj.seek(-1, 2)
            trailer = file_obj.read(1)
            file_obj.seek(0)
            if trailer != b'\x3b':
                result['warnings'].append("GIF file missing proper trailer")
        
        # Check for embedded signatures (polyglot detection)
        other_signatures = []
        for other_ext, sigs in self.FILE_SIGNATURES.items():
            if other_ext != ext:
                for sig in sigs:
                    if sig in header and len(sig) > 2:
                        other_signatures.append(other_ext)
        
        if other_signatures:
            result['warnings'].append(
                f"File contains signatures for other formats: {', '.join(other_signatures)}"
            )
        
        result['matched_signature'] = matched_signature.hex() if matched_signature else None
        result['checks_passed'].append('file_signature_enhanced')
    
    def _validate_mime_type(self, file_obj, result: Dict):
        """Validate MIME type"""
        ext = result['extension']
        expected_mimes = self.MIME_TYPE_MAPPINGS.get(ext, [])
        
        if not expected_mimes:
            result['checks_passed'].append('mime_type')
            return
        
        # Try python-magic first
        detected_mime = None
        if MAGIC_AVAILABLE:
            try:
                file_obj.seek(0)
                file_content = file_obj.read(2048)
                file_obj.seek(0)
                detected_mime = magic.from_buffer(file_content, mime=True)
            except Exception as e:
                security_logger.warning(f"python-magic MIME detection failed: {str(e)}")
        
        # Fallback to mimetypes module
        if not detected_mime:
            detected_mime, _ = mimetypes.guess_type(file_obj.name)
        
        if detected_mime and detected_mime not in expected_mimes:
            raise ValidationError(
                f"MIME type '{detected_mime}' does not match extension '{ext}'. "
                f"Expected: {', '.join(expected_mimes)}"
            )
        
        result['mime_type'] = detected_mime
        result['checks_passed'].append('mime_type')
    
    def _analyze_file_content(self, file_obj, result: Dict):
        """Analyze file content for suspicious patterns"""
        file_obj.seek(0)
        
        # Read file content in chunks to handle large files
        chunk_size = 8192
        suspicious_found = []
        
        while True:
            chunk = file_obj.read(chunk_size)
            if not chunk:
                break
            
            # Check for suspicious patterns
            for pattern in self.SUSPICIOUS_PATTERNS:
                if re.search(pattern, chunk, re.IGNORECASE):
                    pattern_str = pattern.decode('utf-8', errors='ignore')
                    suspicious_found.append(f"Suspicious pattern: {pattern_str}")
        
        file_obj.seek(0)
        
        if suspicious_found:
            raise ValidationError(
                f"Suspicious content detected in file: {'; '.join(suspicious_found)}"
            )
        
        result['checks_passed'].append('content_analysis')
    
    def _detect_malware_signatures(self, file_obj, result: Dict):
        """Detect known malware signatures using advanced scanner"""
        from .malware_scanner import scan_file_for_malware
        
        try:
            # Use advanced malware scanner
            scan_result = scan_file_for_malware(file_obj, result['filename'])
            
            # Add scan results to validation result
            if scan_result['warnings']:
                result['warnings'].extend(scan_result['warnings'])
            
            # The scanner will raise ValidationError if malware is found
            result['malware_scan_result'] = scan_result
            
        except ValidationError:
            # Re-raise malware detection errors
            raise
        except Exception as e:
            # Log scanner errors but continue with basic signature detection
            security_logger.warning(f"Advanced malware scan failed: {str(e)}")
            
            # Fallback to basic signature detection
            file_obj.seek(0)
            header = file_obj.read(1024)  # Read first 1KB
            file_obj.seek(0)
            
            for signature in self.DANGEROUS_SIGNATURES:
                if header.startswith(signature):
                    raise ValidationError(
                        f"Dangerous file signature detected. "
                        f"File appears to be an executable or archive."
                    )
            
            # Special handling for ZIP files
            if header.startswith(b'PK\x03\x04'):
                try:
                    file_obj.seek(0)
                    if zipfile.is_zipfile(file_obj):
                        # Allow ZIP-based formats like DOCX, XLSX, etc.
                        ext = result['extension']
                        if ext not in ['.docx', '.xlsx', '.pptx']:
                            raise ValidationError(
                                "ZIP archives are not allowed for security reasons"
                            )
                    file_obj.seek(0)
                except Exception:
                    file_obj.seek(0)
        
        result['checks_passed'].append('malware_detection')
    
    def _validate_by_type(self, file_obj, result: Dict):
        """Type-specific validation"""
        ext = result['extension']
        file_category = self.allowed_extensions.get(ext, 'default')
        
        if file_category == 'image':
            self._validate_image(file_obj, result)
        elif file_category == 'pdf':
            self._validate_pdf(file_obj, result)
        elif file_category == 'document':
            self._validate_document(file_obj, result)
        
        result['checks_passed'].append('type_specific')
    
    def _validate_image(self, file_obj, result: Dict):
        """Validate image files"""
        try:
            file_obj.seek(0)
            with Image.open(file_obj) as img:
                # Check image dimensions
                max_dimension = getattr(settings, 'MAX_IMAGE_DIMENSION', 8000)
                if img.width > max_dimension or img.height > max_dimension:
                    raise ValidationError(
                        f"Image dimensions ({img.width}x{img.height}) exceed "
                        f"maximum allowed ({max_dimension}x{max_dimension})"
                    )
                
                # Check for reasonable aspect ratio
                aspect_ratio = max(img.width, img.height) / min(img.width, img.height)
                if aspect_ratio > 10:
                    result['warnings'].append(
                        f"Unusual aspect ratio: {aspect_ratio:.2f}"
                    )
                
                # Verify image integrity
                img.verify()
                
                # Check image mode
                if img.mode not in ['RGB', 'RGBA', 'L', 'P', 'CMYK']:
                    result['warnings'].append(f"Unusual image mode: {img.mode}")
                
                # Check for EXIF data (potential privacy concern)
                if hasattr(img, '_getexif') and img._getexif():
                    result['warnings'].append("Image contains EXIF data")
            
            file_obj.seek(0)
            
        except ValidationError:
            raise
        except Exception as e:
            raise ValidationError(f"Invalid or corrupted image file: {str(e)}")
    
    def _validate_pdf(self, file_obj, result: Dict):
        """Validate PDF files"""
        file_obj.seek(0)
        pdf_header = file_obj.read(1024)
        file_obj.seek(0)
        
        # Check PDF version
        if not pdf_header.startswith(b'%PDF-'):
            raise ValidationError("Invalid PDF file format")
        
        # Extract PDF version
        version_match = re.search(rb'%PDF-(\d+\.\d+)', pdf_header)
        if version_match:
            version = version_match.group(1).decode('ascii')
            # Warn about very old PDF versions
            if float(version) < 1.4:
                result['warnings'].append(f"Old PDF version: {version}")
        
        # Check for suspicious PDF content
        suspicious_pdf_patterns = [
            b'/JavaScript',
            b'/JS',
            b'/OpenAction',
            b'/Launch',
            b'/EmbeddedFile',
            b'/RichMedia',
            b'/3D',
        ]
        
        for pattern in suspicious_pdf_patterns:
            if pattern in pdf_header:
                result['warnings'].append(
                    f"PDF contains potentially dangerous feature: {pattern.decode('ascii', errors='ignore')}"
                )
    
    def _validate_document(self, file_obj, result: Dict):
        """Validate document files"""
        ext = result['extension']
        
        # For Office documents, check if they're actually ZIP files
        if ext in ['.docx', '.xlsx', '.pptx']:
            try:
                file_obj.seek(0)
                if not zipfile.is_zipfile(file_obj):
                    raise ValidationError(
                        f"Invalid {ext.upper()} file format"
                    )
                file_obj.seek(0)
            except Exception as e:
                raise ValidationError(f"Error validating {ext.upper()} file: {str(e)}")
        
        # For text files, check encoding
        elif ext in ['.txt', '.csv']:
            try:
                file_obj.seek(0)
                content = file_obj.read(1024)
                file_obj.seek(0)
                
                # Try to decode as UTF-8
                try:
                    content.decode('utf-8')
                except UnicodeDecodeError:
                    # Try other common encodings
                    encodings = ['latin-1', 'cp1252', 'iso-8859-1']
                    decoded = False
                    for encoding in encodings:
                        try:
                            content.decode(encoding)
                            decoded = True
                            result['warnings'].append(f"File uses {encoding} encoding")
                            break
                        except UnicodeDecodeError:
                            continue
                    
                    if not decoded:
                        raise ValidationError("File contains invalid text encoding")
                        
            except Exception as e:
                raise ValidationError(f"Error validating text file: {str(e)}")
    
    def _generate_file_hash(self, file_obj) -> str:
        """Generate SHA-256 hash of file content"""
        file_obj.seek(0)
        hash_sha256 = hashlib.sha256()
        
        for chunk in iter(lambda: file_obj.read(4096), b""):
            hash_sha256.update(chunk)
        
        file_obj.seek(0)
        return hash_sha256.hexdigest()


# Enhanced validation function for Django model fields
def validate_file_security_enhanced(value):
    """
    Enhanced file validation function for Django model fields
    
    Args:
        value: Django UploadedFile object
        
    Raises:
        ValidationError: If validation fails
    """
    validator = EnhancedFileSecurityValidator()
    
    try:
        result = validator.validate_file_comprehensive(value)
        
        # Log warnings if any
        if result['warnings']:
            security_logger.warning(
                f"File validation warnings for {value.name}: "
                f"{'; '.join(result['warnings'])}"
            )
        
        # Return True for Django compatibility
        return True
        
    except ValidationError as e:
        # Log security event
        security_logger.error(
            f"File security validation failed for {value.name}: {str(e)}"
        )
        raise


# Backward compatibility
def validate_file_security(value):
    """
    Backward compatibility wrapper
    """
    return validate_file_security_enhanced(value)
