"""
Enhanced File Security Validator with Bypass Prevention
Task 1.1.2 Implementation - Secure file upload validation
"""

import os
import re
import hashlib
import logging
import mimetypes
import tempfile
import subprocess
import json
from typing import List, Dict, Optional, Tuple, Union
from datetime import datetime, timedelta
from django.core.exceptions import ValidationError
from django.conf import settings
from django.core.files.uploadedfile import SimpleUploadedFile

# Import existing components
from .file_security import EnhancedFileSecurityValidator as BaseValidator
from .malware_scanner import scan_file_for_malware

# Security logger
security_logger = logging.getLogger('security')

# Try to import optional dependencies
try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    security_logger.warning("PIL not available. Image validation will be limited.")

try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False
    security_logger.warning("python-magic not available. File type detection will be limited.")


class BypassPreventionValidator(BaseValidator):
    """
    Enhanced file security validator with comprehensive bypass prevention
    """
    
    # Enhanced bypass patterns
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
    
    # Enhanced suspicious patterns
    ENHANCED_SUSPICIOUS_PATTERNS = [
        # Obfuscated PHP
        rb'eval\s*\(\s*base64_decode',
        rb'eval\s*\(\s*gzinflate',
        rb'eval\s*\(\s*str_rot13',
        rb'eval\s*\(\s*gzuncompress',
        rb'assert\s*\(\s*base64_decode',
        rb'preg_replace\s*\(\s*["\']/.*/e["\']',
        
        # Obfuscated JavaScript
        rb'eval\s*\(\s*unescape',
        rb'eval\s*\(\s*String\.fromCharCode',
        rb'Function\s*\(\s*["\'][^"\']*["\']',
        rb'setTimeout\s*\(\s*["\'][^"\']*["\']',
        rb'setInterval\s*\(\s*["\'][^"\']*["\']',
        
        # SQL injection (advanced)
        rb'UNION\s+ALL\s+SELECT',
        rb'UNION\s+SELECT\s+NULL',
        rb'ORDER\s+BY\s+\d+',
        rb'GROUP\s+BY\s+\d+',
        rb'HAVING\s+\d+=\d+',
        rb'WAITFOR\s+DELAY',
        rb'BENCHMARK\s*\(',
        rb'SLEEP\s*\(',
        rb'pg_sleep\s*\(',
        
        # Command injection (advanced)
        rb'\$\(.*\)',  # Command substitution
        rb'`.*`',      # Backticks
        rb';\s*\w+\s*>',  # Output redirection
        rb'\|\s*\w+',     # Pipes
        rb'&&\s*\w+',     # Command chaining
        rb'\|\|\s*\w+',   # OR chaining
        
        # File inclusion
        rb'include\s*\(\s*["\'][^"\']*\.\.',
        rb'require\s*\(\s*["\'][^"\']*\.\.',
        rb'include_once\s*\(\s*["\'][^"\']*\.\.',
        rb'require_once\s*\(\s*["\'][^"\']*\.\.',
        
        # Remote file inclusion
        rb'include\s*\(\s*["\']https?://',
        rb'require\s*\(\s*["\']https?://',
        rb'file_get_contents\s*\(\s*["\']https?://',
        rb'fopen\s*\(\s*["\']https?://',
        
        # Webshell patterns
        rb'c99shell',
        rb'r57shell',
        rb'wso\s*shell',
        rb'b374k',
        rb'adminer\.php',
        rb'phpMyAdmin',
        
        # Cryptocurrency mining
        rb'stratum\+tcp://',
        rb'cryptonight',
        rb'monero',
        rb'bitcoin',
        rb'mining\s*pool',
        
        # Suspicious network activity
        rb'curl\s+-s\s+.*\|\s*sh',
        rb'wget\s+.*\|\s*sh',
        rb'nc\s+-l\s+-p',
        rb'netcat\s+-l\s+-p',
        rb'/dev/tcp/',
        rb'/dev/udp/',
    ]
    
    def __init__(self, *args, **kwargs):
        """Initialize enhanced validator"""
        super().__init__(*args, **kwargs)
        
        # Compile bypass patterns
        self.bypass_patterns = [re.compile(pattern, re.IGNORECASE) 
                               for pattern in self.BYPASS_EXTENSIONS]
        
        # Compile enhanced suspicious patterns
        self.enhanced_patterns = [re.compile(pattern, re.IGNORECASE | re.MULTILINE) 
                                 for pattern in self.ENHANCED_SUSPICIOUS_PATTERNS]
        
        # Initialize quarantine directory
        self.quarantine_dir = getattr(settings, 'FILE_QUARANTINE_DIR', 
                                    os.path.join(settings.MEDIA_ROOT, 'quarantine'))
        os.makedirs(self.quarantine_dir, exist_ok=True)
    
    def validate_file_comprehensive(self, file_obj, client_ip: str = None, 
                                  user_id: str = None) -> Dict[str, any]:
        """
        Comprehensive file validation with bypass prevention
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
            'scan_timestamp': datetime.now().isoformat(),
            'threat_level': 'LOW'
        }
        
        try:
            # Enhanced validation steps
            self._validate_basic_info_enhanced(file_obj, validation_result)
            self._detect_bypass_attempts(file_obj, validation_result)
            self._validate_extension_enhanced(file_obj, validation_result)
            self._validate_file_size(file_obj, validation_result)
            self._validate_signature_enhanced(file_obj, validation_result)
            self._validate_mime_type_enhanced(file_obj, validation_result)
            self._analyze_content_enhanced(file_obj, validation_result)
            self._detect_polyglot_files(file_obj, validation_result)
            self._detect_steganography(file_obj, validation_result)
            self._perform_malware_scan(file_obj, validation_result)
            
            # Calculate threat level
            self._calculate_threat_level(validation_result)
            
            # Generate file hash
            validation_result['file_hash'] = self._generate_file_hash(file_obj)
            
            # Final assessment
            validation_result['is_safe'] = (
                len(validation_result['warnings']) == 0 and 
                len(validation_result['bypass_attempts']) == 0 and
                validation_result['threat_level'] in ['LOW', 'MEDIUM']
            )
            
            # Log results
            if validation_result['is_safe']:
                security_logger.info(f"File validation passed: {file_obj.name}")
            else:
                security_logger.warning(
                    f"File validation failed: {file_obj.name} - "
                    f"Threat level: {validation_result['threat_level']}"
                )
            
            return validation_result
            
        except ValidationError as e:
            security_logger.error(f"File validation error: {file_obj.name} - {str(e)}")
            raise
        except Exception as e:
            security_logger.error(f"Unexpected validation error: {file_obj.name} - {str(e)}")
            raise ValidationError(f"File validation failed: {str(e)}")
    
    def _validate_basic_info_enhanced(self, file_obj, result: Dict):
        """Enhanced basic file information validation"""
        if not file_obj.name:
            raise ValidationError("File name is required")
        
        if file_obj.size <= 0:
            raise ValidationError("File is empty")
        
        # Check for suspicious filename patterns
        suspicious_patterns = [
            r'\.\./',  # Path traversal
            r'[<>:"|?*]',  # Invalid filename characters
            r'^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|$)',  # Windows reserved names
            r'\x00',  # Null bytes
            r'[\x01-\x1f]',  # Control characters
            r'^\.',  # Hidden files (Unix)
            r'\s+$',  # Trailing whitespace
            r'^\s+',  # Leading whitespace
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, file_obj.name, re.IGNORECASE):
                if pattern == r'^\.' and len(file_obj.name) > 1:
                    result['warnings'].append(f"Hidden file detected: {file_obj.name}")
                else:
                    raise ValidationError(f"Suspicious filename pattern: {file_obj.name}")
        
        # Check filename length
        if len(file_obj.name) > 255:
            raise ValidationError("Filename too long")
        
        # Check for Unicode normalization attacks
        try:
            import unicodedata
            normalized = unicodedata.normalize('NFKC', file_obj.name)
            if normalized != file_obj.name:
                result['warnings'].append("Filename contains Unicode normalization issues")
        except Exception:
            pass
        
        result['checks_passed'].append('basic_info_enhanced')
    
    def _detect_bypass_attempts(self, file_obj, result: Dict):
        """Detect various bypass attempts"""
        filename = file_obj.name.lower()
        
        # Check for extension bypass patterns
        for pattern in self.bypass_patterns:
            if pattern.search(filename):
                result['bypass_attempts'].append(f"Extension bypass: {pattern.pattern}")
        
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
        
        # Check for RTLO (Right-to-Left Override) attacks
        if '\u202e' in file_obj.name or '\u202d' in file_obj.name:
            result['bypass_attempts'].append("RTLO character detected in filename")
        
        # Check for homograph attacks
        suspicious_chars = ['а', 'е', 'о', 'р', 'с', 'х', 'у']  # Cyrillic lookalikes
        for char in suspicious_chars:
            if char in file_obj.name:
                result['bypass_attempts'].append("Homograph attack character detected")
                break
        
        result['checks_passed'].append('bypass_detection')
    
    def _validate_extension_enhanced(self, file_obj, result: Dict):
        """Enhanced extension validation"""
        filename = file_obj.name.lower()
        parts = filename.split('.')
        
        if len(parts) < 2:
            raise ValidationError("File must have an extension")
        
        # Get all extensions
        extensions = [f'.{part}' for part in parts[1:]]
        final_ext = extensions[-1]
        
        # Check final extension
        if final_ext not in self.allowed_extensions:
            allowed_list = ', '.join(self.allowed_extensions.keys())
            raise ValidationError(f"Extension '{final_ext}' not allowed. Allowed: {allowed_list}")
        
        # Check for dangerous intermediate extensions
        dangerous_exts = [
            '.php', '.asp', '.jsp', '.exe', '.bat', '.cmd', '.scr', '.com', '.pif',
            '.vbs', '.js', '.jar', '.py', '.pl', '.rb', '.sh', '.bash', '.cgi',
            '.htaccess', '.htpasswd', '.config', '.ini', '.conf'
        ]
        
        for ext in extensions[:-1]:
            if ext in dangerous_exts:
                result['bypass_attempts'].append(f"Dangerous intermediate extension: {ext}")
        
        # Check for case variation bypass
        original_ext = os.path.splitext(file_obj.name)[1]
        if original_ext != original_ext.lower():
            result['warnings'].append(f"Mixed case extension: {original_ext}")
        
        result['extension'] = final_ext
        result['checks_passed'].append('extension_enhanced')
    
    def _validate_signature_enhanced(self, file_obj, result: Dict):
        """Enhanced file signature validation"""
        ext = result['extension']
        expected_signatures = self.FILE_SIGNATURES.get(ext, [])
        
        if not expected_signatures:
            result['checks_passed'].append('signature_enhanced')
            return
        
        # Read file header
        file_obj.seek(0)
        header = file_obj.read(2048)  # Read more for better analysis
        file_obj.seek(0)
        
        # Validate primary signature
        signature_match = False
        for signature in expected_signatures:
            if header.startswith(signature):
                signature_match = True
                break
        
        if not signature_match:
            raise ValidationError(f"File signature mismatch for extension '{ext}'")
        
        # Enhanced signature checks by file type
        if ext in ['.jpg', '.jpeg']:
            self._validate_jpeg_structure(file_obj, result)
        elif ext == '.png':
            self._validate_png_structure(file_obj, result)
        elif ext == '.pdf':
            self._validate_pdf_structure(file_obj, result)
        elif ext == '.gif':
            self._validate_gif_structure(file_obj, result)
        
        result['checks_passed'].append('signature_enhanced')
    
    def _validate_jpeg_structure(self, file_obj, result: Dict):
        """Validate JPEG file structure"""
        file_obj.seek(-2, 2)
        end_marker = file_obj.read(2)
        file_obj.seek(0)
        
        if end_marker != b'\xff\xd9':
            result['warnings'].append("JPEG missing proper end marker")
        
        # Check for EXIF data
        file_obj.seek(0)
        header = file_obj.read(1024)
        file_obj.seek(0)
        
        if b'Exif' in header:
            result['warnings'].append("JPEG contains EXIF data")
    
    def _validate_png_structure(self, file_obj, result: Dict):
        """Validate PNG file structure"""
        file_obj.seek(0)
        header = file_obj.read(50)
        file_obj.seek(0)
        
        if b'IHDR' not in header:
            raise ValidationError("PNG missing IHDR chunk")
        
        # Check for proper end
        file_obj.seek(-12, 2)
        end_chunk = file_obj.read(12)
        file_obj.seek(0)
        
        if b'IEND' not in end_chunk:
            result['warnings'].append("PNG missing IEND chunk")
    
    def _validate_pdf_structure(self, file_obj, result: Dict):
        """Validate PDF file structure"""
        file_obj.seek(0)
        header = file_obj.read(1024)
        file_obj.seek(0)
        
        # Check for suspicious PDF features
        suspicious_features = [
            b'/JavaScript', b'/JS', b'/OpenAction', b'/Launch',
            b'/EmbeddedFile', b'/RichMedia', b'/3D', b'/GoToR'
        ]
        
        for feature in suspicious_features:
            if feature in header:
                result['warnings'].append(f"PDF contains suspicious feature: {feature.decode('ascii', errors='ignore')}")
    
    def _validate_gif_structure(self, file_obj, result: Dict):
        """Validate GIF file structure"""
        file_obj.seek(-1, 2)
        trailer = file_obj.read(1)
        file_obj.seek(0)
        
        if trailer != b'\x3b':
            result['warnings'].append("GIF missing proper trailer")
    
    def _validate_mime_type_enhanced(self, file_obj, result: Dict):
        """Enhanced MIME type validation"""
        ext = result['extension']
        expected_mimes = self.MIME_TYPE_MAPPINGS.get(ext, [])
        
        if not expected_mimes:
            result['checks_passed'].append('mime_type_enhanced')
            return
        
        detected_mimes = []
        
        # Multiple detection methods
        if MAGIC_AVAILABLE:
            try:
                file_obj.seek(0)
                content = file_obj.read(8192)
                file_obj.seek(0)
                magic_mime = magic.from_buffer(content, mime=True)
                if magic_mime:
                    detected_mimes.append(magic_mime)
            except Exception:
                pass
        
        # Fallback to mimetypes
        mime_type, _ = mimetypes.guess_type(file_obj.name)
        if mime_type:
            detected_mimes.append(mime_type)
        
        # Validate detected types
        valid_mime_found = any(mime in expected_mimes for mime in detected_mimes)
        
        if detected_mimes and not valid_mime_found:
            raise ValidationError(f"MIME type mismatch: detected {detected_mimes}, expected {expected_mimes}")
        
        result['detected_mime_types'] = detected_mimes
        result['checks_passed'].append('mime_type_enhanced')
    
    def _analyze_content_enhanced(self, file_obj, result: Dict):
        """Enhanced content analysis"""
        file_obj.seek(0)
        
        # Read content in chunks with overlap
        chunk_size = 16384
        overlap_size = 1024
        suspicious_found = []
        previous_tail = b''
        
        while True:
            chunk = file_obj.read(chunk_size)
            if not chunk:
                break
            
            analysis_chunk = previous_tail + chunk
            
            # Check enhanced suspicious patterns
            for pattern in self.enhanced_patterns:
                matches = list(pattern.finditer(analysis_chunk))
                for match in matches:
                    suspicious_found.append({
                        'pattern': pattern.pattern.decode('utf-8', errors='ignore'),
                        'match': match.group().decode('utf-8', errors='ignore')[:100],
                        'position': file_obj.tell() - len(chunk) + match.start() - len(previous_tail)
                    })
            
            previous_tail = chunk[-overlap_size:] if len(chunk) >= overlap_size else chunk
        
        file_obj.seek(0)
        
        if suspicious_found:
            # Quarantine file
            self._quarantine_file(file_obj, result, suspicious_found)
            patterns = [item['pattern'][:50] for item in suspicious_found[:3]]
            raise ValidationError(f"Malicious content detected: {'; '.join(patterns)}")
        
        result['checks_passed'].append('content_analysis_enhanced')
    
    def _detect_polyglot_files(self, file_obj, result: Dict):
        """Detect polyglot files"""
        file_obj.seek(0)
        header = file_obj.read(2048)
        file_obj.seek(0)
        
        polyglot_checks = [
            (b'%PDF-', b'<html', "PDF with HTML"),
            (b'%PDF-', b'<script', "PDF with JavaScript"),
            (b'\xff\xd8\xff', b'<script', "JPEG with script"),
            (b'\xff\xd8\xff', b'<?php', "JPEG with PHP"),
            (b'\x89PNG', b'<?php', "PNG with PHP"),
            (b'GIF8', b'<script', "GIF with script"),
        ]
        
        for sig1, sig2, desc in polyglot_checks:
            if sig1 in header and sig2 in header:
                result['bypass_attempts'].append(f"Polyglot file: {desc}")
        
        result['checks_passed'].append('polyglot_detection')
    
    def _detect_steganography(self, file_obj, result: Dict):
        """Basic steganography detection"""
        ext = result.get('extension', '')
        
        if ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp'] and PIL_AVAILABLE:
            try:
                file_obj.seek(0)
                with Image.open(file_obj) as img:
                    # Check for extensive metadata
                    if hasattr(img, '_getexif') and img._getexif():
                        exif_data = img._getexif()
                        if exif_data and len(exif_data) > 20:
                            result['warnings'].append("Image contains extensive metadata")
                file_obj.seek(0)
            except Exception:
                pass
        
        result['checks_passed'].append('steganography_detection')
    
    def _perform_malware_scan(self, file_obj, result: Dict):
        """Perform malware scanning"""
        try:
            scan_result = scan_file_for_malware(file_obj, result['filename'])
            result['malware_scan'] = scan_result
            
            if not scan_result['is_clean']:
                result['bypass_attempts'].extend(scan_result['threats_detected'])
        
        except ValidationError:
            raise
        except Exception as e:
            result['warnings'].append(f"Malware scan error: {str(e)}")
        
        result['checks_passed'].append('malware_scan')
    
    def _calculate_threat_level(self, result: Dict):
        """Calculate overall threat level"""
        threat_score = 0
        
        # Score based on findings
        threat_score += len(result['bypass_attempts']) * 10
        threat_score += len(result['warnings']) * 3
        
        # Specific threat indicators
        if any('polyglot' in attempt.lower() for attempt in result['bypass_attempts']):
            threat_score += 20
        
        if any('malicious' in attempt.lower() for attempt in result['bypass_attempts']):
            threat_score += 30
        
        if result.get('quarantined', False):
            threat_score += 50
        
        # Determine threat level
        if threat_score >= 50:
            result['threat_level'] = 'CRITICAL'
        elif threat_score >= 30:
            result['threat_level'] = 'HIGH'
        elif threat_score >= 15:
            result['threat_level'] = 'MEDIUM'
        else:
            result['threat_level'] = 'LOW'
    
    def _quarantine_file(self, file_obj, result: Dict, suspicious_content: List[Dict]):
        """Quarantine suspicious files"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            file_hash = hashlib.md5(file_obj.read()).hexdigest()[:8]
            file_obj.seek(0)
            
            quarantine_filename = f"{timestamp}_{file_hash}_{os.path.basename(file_obj.name)}"
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_filename)
            
            # Save file
            with open(quarantine_path, 'wb') as qf:
                file_obj.seek(0)
                qf.write(file_obj.read())
                file_obj.seek(0)
            
            # Save report
            report_data = {
                'original_filename': file_obj.name,
                'quarantine_timestamp': datetime.now().isoformat(),
                'file_size': file_obj.size,
                'suspicious_content': suspicious_content,
                'validation_result': result
            }
            
            with open(quarantine_path + '.json', 'w') as rf:
                json.dump(report_data, rf, indent=2, default=str)
            
            result['quarantined'] = True
            result['quarantine_path'] = quarantine_path
            
            security_logger.warning(f"File quarantined: {file_obj.name} -> {quarantine_path}")
            
        except Exception as e:
            security_logger.error(f"Quarantine failed: {str(e)}")
    
    def _generate_file_hash(self, file_obj) -> str:
        """Generate SHA-256 hash"""
        file_obj.seek(0)
        hash_sha256 = hashlib.sha256()
        
        for chunk in iter(lambda: file_obj.read(4096), b""):
            hash_sha256.update(chunk)
        
        file_obj.seek(0)
        return hash_sha256.hexdigest()


# Enhanced validation function for Django models
def validate_file_security_bypass_prevention(value):
    """
    Enhanced file validation with bypass prevention
    """
    validator = BypassPreventionValidator(enable_rate_limiting=False)
    
    try:
        result = validator.validate_file_comprehensive(value)
        
        if not result['is_safe']:
            threats = result['bypass_attempts'] + result['warnings']
            raise ValidationError(f"File security validation failed: {'; '.join(threats[:3])}")
        
        return True
        
    except ValidationError:
        raise
    except Exception as e:
        security_logger.error(f"File validation error: {str(e)}")
        raise ValidationError(f"File validation failed: {str(e)}")


# Global validator instance
enhanced_file_validator = BypassPreventionValidator()