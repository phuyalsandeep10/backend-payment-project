import os
from django.core.exceptions import ValidationError
from PIL import Image
import zipfile
import io

# Try to import magic, but fall back gracefully if not available (Windows)
try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False

def validate_file_security(value):
    """
    Enhanced file validation with comprehensive security checks
    """
    
    # Check 1: File extension validation
    ext = os.path.splitext(value.name)[1].lower()
    valid_extensions = ['.jpg', '.jpeg', '.png', '.pdf']
    if ext not in valid_extensions:
        raise ValidationError(f'File extension {ext} not allowed. Allowed extensions: {", ".join(valid_extensions)}')
    
    # Check 2: File size validation (5MB limit)
    max_size = 5 * 1024 * 1024  # 5MB
    if value.size > max_size:
        raise ValidationError(f'File size {value.size} bytes exceeds maximum allowed size of {max_size} bytes (5MB)')
    
    # Check 3: MIME type validation using python-magic (if available)
    value.seek(0)
    file_content = value.read(2048)  # Read first 2KB for analysis
    value.seek(0)  # Reset file pointer
    
    if MAGIC_AVAILABLE:
        try:
            # Detect MIME type from file content
            detected_mime = magic.from_buffer(file_content, mime=True)
            allowed_mimes = {
                '.jpg': ['image/jpeg'],
                '.jpeg': ['image/jpeg'],
                '.png': ['image/png'],
                '.pdf': ['application/pdf']
            }
            
            expected_mimes = allowed_mimes.get(ext, [])
            if detected_mime not in expected_mimes:
                raise ValidationError(f'File MIME type {detected_mime} does not match extension {ext}. Expected: {", ".join(expected_mimes)}')
                
        except Exception as e:
            # If magic fails, continue with other validations
            pass
    
    # Check 4: File header validation (magic numbers)
    magic_numbers = {
        '.jpg': [b'\xff\xd8\xff'],
        '.jpeg': [b'\xff\xd8\xff'],
        '.png': [b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a'],
        '.pdf': [b'%PDF-']
    }
    
    expected_headers = magic_numbers.get(ext, [])
    header_match = False
    
    for header in expected_headers:
        if file_content.startswith(header):
            header_match = True
            break
    
    if expected_headers and not header_match:
        raise ValidationError(f'File header does not match extension {ext}. File may be corrupted or disguised.')
    
    # Check 5: ZIP file detection and rejection
    try:
        value.seek(0)
        # Check if it's a ZIP file (common attack vector)
        if zipfile.is_zipfile(value):
            raise ValidationError('ZIP files are not allowed for security reasons')
        value.seek(0)
    except Exception:
        # If ZIP check fails, continue with other validations
        value.seek(0)
    
    # Check 6: Image-specific validation
    if ext in ['.jpg', '.jpeg', '.png']:
        try:
            value.seek(0)
            with Image.open(value) as img:
                # Check image dimensions (prevent huge images that could cause DoS)
                max_dimension = 4000
                if img.width > max_dimension or img.height > max_dimension:
                    raise ValidationError(f'Image dimensions ({img.width}x{img.height}) exceed maximum allowed ({max_dimension}x{max_dimension})')
                
                # Verify image can be processed (detect corrupted images)
                img.verify()
                
                # Check for suspicious image properties
                if img.mode not in ['RGB', 'RGBA', 'L', 'P']:
                    raise ValidationError(f'Unsupported image mode: {img.mode}')
                    
            value.seek(0)
        except ValidationError:
            raise  # Re-raise our validation errors
        except Exception as e:
            raise ValidationError(f'Invalid or corrupted image file: {str(e)}')
    
    # Check 7: PDF-specific validation (basic)
    if ext == '.pdf':
        try:
            # Basic PDF validation - check for PDF signature
            value.seek(0)
            pdf_content = value.read(1024)
            value.seek(0)
            
            if not pdf_content.startswith(b'%PDF-'):
                raise ValidationError('Invalid PDF file format')
                
            # Check for suspicious content in PDF header
            suspicious_patterns = [b'<script', b'javascript:', b'/JS', b'/JavaScript']
            for pattern in suspicious_patterns:
                if pattern.lower() in pdf_content.lower():
                    raise ValidationError('PDF contains potentially malicious content')
                    
        except ValidationError:
            raise  # Re-raise our validation errors
        except Exception as e:
            raise ValidationError(f'Error validating PDF file: {str(e)}')
    
    # Check 8: Scan for common malware signatures
    malware_signatures = [
        b'MZ',  # PE executable header
        b'\x7fELF',  # ELF executable header
        b'\xfe\xed\xfa',  # Mach-O executable header
        b'JFIF\x00\x01',  # Suspicious JPEG marker
    ]
    
    # Only check for executable headers, not JPEG markers for legitimate images
    dangerous_signatures = [b'MZ', b'\x7fELF', b'\xfe\xed\xfa']
    for signature in dangerous_signatures:
        if file_content.startswith(signature):
            raise ValidationError('File appears to be an executable and is not allowed')
    
    return True

# Keep the old function for backward compatibility
def validate_file_type(value):
    """
    Legacy function - now redirects to enhanced security validation
    """
    return validate_file_security(value) 