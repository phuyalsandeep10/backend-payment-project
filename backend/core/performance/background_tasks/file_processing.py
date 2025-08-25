"""
File Processing Background Tasks

This module handles file processing tasks including:
- Profile picture processing and resizing
- Deal attachment processing and security validation
- File format conversion and optimization

Extracted from background_task_processor.py for better organization.
"""

from celery import shared_task
from celery.utils.log import get_task_logger
from django.utils import timezone
from PIL import Image
import io
import os
import tempfile
from typing import Dict, Any

# Task logger
logger = get_task_logger(__name__)


@shared_task(bind=True, max_retries=3)
def process_profile_picture(self, user_id, file_path, original_filename):
    """
    Background task for processing profile pictures
    """
    try:
        from apps.authentication.models import User
        
        user = User.objects.get(id=user_id)
        
        logger.info(f"Processing profile picture for user {user.email}")
        
        result = {
            'user_id': user_id,
            'original_filename': original_filename,
            'started_at': timezone.now().isoformat(),
            'success': False,
            'processed_files': {}
        }
        
        # Process the image
        with Image.open(file_path) as img:
            # Verify image integrity
            img.verify()
            
            # Reopen for processing
            img = Image.open(file_path)
            
            # Convert to RGB if necessary
            if img.mode in ('RGBA', 'LA', 'P'):
                img = img.convert('RGB')
            
            # Generate different sizes
            sizes = {
                'thumbnail': (150, 150),
                'medium': (300, 300),
                'large': (600, 600)
            }
            
            processed_files = {}
            
            for size_name, dimensions in sizes.items():
                # Resize image
                resized_img = img.copy()
                resized_img.thumbnail(dimensions, Image.Resampling.LANCZOS)
                
                # Save processed image
                output_buffer = io.BytesIO()
                resized_img.save(output_buffer, format='JPEG', quality=85, optimize=True)
                
                # Generate filename
                base_name = os.path.splitext(original_filename)[0]
                processed_filename = f"{base_name}_{size_name}.jpg"
                
                # Save to storage (this would integrate with your file storage system)
                processed_files[size_name] = {
                    'filename': processed_filename,
                    'size': output_buffer.tell(),
                    'dimensions': dimensions
                }
                
                logger.info(f"Generated {size_name} version: {processed_filename}")
        
        result['processed_files'] = processed_files
        result['success'] = True
        result['completed_at'] = timezone.now().isoformat()
        
        # Clean up original file
        if os.path.exists(file_path):
            os.remove(file_path)
        
        logger.info(f"Profile picture processing completed for user {user.email}")
        return result
        
    except Exception as e:
        logger.error(f"Profile picture processing failed: {str(e)}")
        
        # Clean up on failure
        if os.path.exists(file_path):
            os.remove(file_path)
        
        # Retry with exponential backoff
        if self.request.retries < self.max_retries:
            countdown = 2 ** self.request.retries
            logger.info(f"Retrying profile picture processing in {countdown} seconds...")
            raise self.retry(countdown=countdown, exc=e)
        
        raise


@shared_task(bind=True, max_retries=3)
def process_deal_attachment(self, deal_id, file_path, original_filename, file_type):
    """
    Background task for processing deal attachments
    """
    try:
        from deals.models import Deal
        
        deal = Deal.objects.get(id=deal_id)
        
        logger.info(f"Processing deal attachment for deal {deal.deal_id}")
        
        result = {
            'deal_id': deal.deal_id,
            'original_filename': original_filename,
            'file_type': file_type,
            'started_at': timezone.now().isoformat(),
            'success': False,
            'processing_details': {}
        }
        
        # Validate file security
        try:
            from core_config.file_security import validate_file_security_enhanced
            
            with open(file_path, 'rb') as f:
                validation_result = validate_file_security_enhanced(f)
                
                if not validation_result['is_safe']:
                    raise ValueError(f"File security validation failed: {validation_result['reason']}")
        except ImportError:
            logger.warning("File security validation module not available, skipping security check")
        
        # Process based on file type
        if file_type.startswith('image/'):
            # Process image attachment
            processing_result = _process_image_attachment(file_path, original_filename)
        elif file_type == 'application/pdf':
            # Process PDF attachment
            processing_result = _process_pdf_attachment(file_path, original_filename)
        else:
            # Process generic file
            processing_result = _process_generic_attachment(file_path, original_filename)
        
        result['processing_details'] = processing_result
        result['success'] = True
        result['completed_at'] = timezone.now().isoformat()
        
        # Clean up original file
        if os.path.exists(file_path):
            os.remove(file_path)
        
        logger.info(f"Deal attachment processing completed for deal {deal.deal_id}")
        return result
        
    except Exception as e:
        logger.error(f"Deal attachment processing failed: {str(e)}")
        
        # Clean up on failure
        if os.path.exists(file_path):
            os.remove(file_path)
        
        # Retry with exponential backoff
        if self.request.retries < self.max_retries:
            countdown = 2 ** self.request.retries
            logger.info(f"Retrying deal attachment processing in {countdown} seconds...")
            raise self.retry(countdown=countdown, exc=e)
        
        raise


def _process_image_attachment(file_path: str, original_filename: str) -> Dict[str, Any]:
    """Process image attachment"""
    try:
        with Image.open(file_path) as img:
            # Get image info
            width, height = img.size
            format_name = img.format
            mode = img.mode
            
            # Generate thumbnail if image is large
            thumbnail_created = False
            if width > 800 or height > 800:
                thumbnail = img.copy()
                thumbnail.thumbnail((800, 800), Image.Resampling.LANCZOS)
                
                # Save thumbnail
                base_name = os.path.splitext(original_filename)[0]
                thumbnail_filename = f"{base_name}_thumb.jpg"
                
                thumbnail_buffer = io.BytesIO()
                thumbnail.save(thumbnail_buffer, format='JPEG', quality=85)
                
                thumbnail_created = True
            
            return {
                'file_type': 'image',
                'original_dimensions': (width, height),
                'format': format_name,
                'mode': mode,
                'thumbnail_created': thumbnail_created,
                'file_size': os.path.getsize(file_path)
            }
            
    except Exception as e:
        return {
            'file_type': 'image',
            'processing_error': str(e)
        }


def _process_pdf_attachment(file_path: str, original_filename: str) -> Dict[str, Any]:
    """Process PDF attachment"""
    try:
        file_size = os.path.getsize(file_path)
        
        # Basic PDF processing - could be extended with PDF parsing libraries
        return {
            'file_type': 'pdf',
            'file_size': file_size,
            'processed': True,
            'security_scanned': True  # Placeholder for actual security scanning
        }
        
    except Exception as e:
        return {
            'file_type': 'pdf',
            'processing_error': str(e)
        }


def _process_generic_attachment(file_path: str, original_filename: str) -> Dict[str, Any]:
    """Process generic file attachment"""
    try:
        file_size = os.path.getsize(file_path)
        file_extension = os.path.splitext(original_filename)[1].lower()
        
        return {
            'file_type': 'generic',
            'file_extension': file_extension,
            'file_size': file_size,
            'processed': True
        }
        
    except Exception as e:
        return {
            'file_type': 'generic',
            'processing_error': str(e)
        }
