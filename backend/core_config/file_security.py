"""
Enhanced File Security Validator
Comprehensive file validation with bypass prevention and malware detection
"""

import os
import re
import hashlib
import logging
import mimetypes
from typing import List, Dict, Optional, Tuple
from django.core.exceptions import ValidationError
from django.conf import settings
from PIL import Image
import zipfile
import io

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
    """
    
    # Maximum file sizes by type (in bytes)
    MAX_FILE_SIZES = {
        'image': 10 * 1024 * 1024,  # 10MB for images
        'pdf': 25 * 1024 * 1024,    # 25MB for PDFs
        'document': 50 * 1024 * 1024, # 50MB for documents
        'default': 5 * 1024 * 1024   # 5MB default
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
    
    # Suspicious content patterns
    SUSPICIOUS_PATTERNS = [
        # Script patterns
        rb'<script[^>]*>',
        rb'javascript:',
        rb'vbscript:',
        rb'data:text/html',
        rb'data:application/javascript',
        
        # Executable patterns
        rb'exec\(',
        rb'eval\(',
        rb'system\(',
        rb'shell_exec\(',
        rb'passthru\(',
        rb'proc_open\(',
        
        # PHP patterns
        rb'<\?php',
        rb'<\?=',
        rb'<%',
        
        # SQL patterns
        rb'DROP\s+TABLE',
        rb'DELETE\s+FROM',
        rb'INSERT\s+INTO',
        rb'UPDATE\s+SET',
        
        # Command injection patterns
        rb';\s*rm\s+-rf',
        rb';\s*cat\s+/etc/passwd',
        rb';\s*wget\s+',
        rb';\s*curl\s+',
    ]
    
    def __init__(self, allowed_extensions: Optional[List[str]] = None):
        """
        Initialize the validator
        
        Args:
            allowed_extensions: List of allowed extensions (overrides default)
        """
        if allowed_extensions:
            self.allowed_extensions = {ext.lower(): 'custom' for ext in allowed_extensions}
        else:
            self.allowed_extensions = self.ALLOWED_EXTENSIONS
    
    def validate_file_comprehensive(self, file_obj) -> Dict[str, any]:
        """
        Comprehensive file validation with detailed results
        
        Args:
            file_obj: Django UploadedFile object
            
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
            'checks_passed': []
        }
        
        try:
            # Step 1: Basic file information validation
            self._validate_basic_info(file_obj, validation_result)
            
            # Step 2: File extension validation
            self._validate_extension(file_obj, validation_result)
            
            # Step 3: File size validation
            self._validate_file_size(file_obj, validation_result)
            
            # Step 4: File signature validation
            self._validate_file_signature(file_obj, validation_result)
            
            # Step 5: MIME type validation
            self._validate_mime_type(file_obj, validation_result)
            
            # Step 6: Content analysis
            self._analyze_file_content(file_obj, validation_result)
            
            # Step 7: Malware signature detection
            self._detect_malware_signatures(file_obj, validation_result)
            
            # Step 8: Type-specific validation
            self._validate_by_type(file_obj, validation_result)
            
            # Step 9: Generate file hash for integrity
            validation_result['file_hash'] = self._generate_file_hash(file_obj)
            
            # Step 10: Final security assessment
            validation_result['is_safe'] = len(validation_result['warnings']) == 0
            
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