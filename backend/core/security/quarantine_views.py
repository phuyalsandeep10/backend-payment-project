"""
Quarantine Management Views
Task 1.2.2 Implementation - Web interface for quarantine review workflow
"""

import os
import json
import shutil
from datetime import datetime, timedelta
from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse, HttpResponse, Http404
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required, user_passes_test
from django.conf import settings
from django.utils import timezone
from django.core.paginator import Paginator
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
import logging

logger = logging.getLogger(__name__)


def is_admin_or_security_staff(user):
    """Check if user has permission to manage quarantine"""
    return user.is_superuser or user.groups.filter(name__in=['security_admin', 'system_admin']).exists()


@login_required
@user_passes_test(is_admin_or_security_staff)
def quarantine_dashboard(request):
    """Main quarantine management dashboard"""
    quarantine_dir = getattr(
        settings, 
        'FILE_QUARANTINE_DIR', 
        os.path.join(settings.MEDIA_ROOT, 'quarantine')
    )
    
    if not os.path.exists(quarantine_dir):
        os.makedirs(quarantine_dir, exist_ok=True)
    
    # Get quarantine statistics
    stats = get_quarantine_stats(quarantine_dir)
    
    context = {
        'stats': stats,
        'quarantine_dir': quarantine_dir
    }
    
    return render(request, 'quarantine/dashboard.html', context)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_quarantined_files(request):
    """API endpoint to list quarantined files with pagination"""
    if not is_admin_or_security_staff(request.user):
        return Response({'error': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)
    
    quarantine_dir = getattr(
        settings, 
        'FILE_QUARANTINE_DIR', 
        os.path.join(settings.MEDIA_ROOT, 'quarantine')
    )
    
    try:
        files = []
        
        for filename in os.listdir(quarantine_dir):
            if filename.endswith('.json'):
                report_path = os.path.join(quarantine_dir, filename)
                file_path = report_path[:-5]  # Remove .json extension
                
                if os.path.exists(file_path):
                    try:
                        with open(report_path, 'r') as f:
                            report = json.load(f)
                        
                        validation_result = report.get('validation_result', {})
                        
                        file_info = {
                            'id': filename[:-5],
                            'original_name': report.get('original_filename', 'Unknown'),
                            'quarantine_date': report.get('quarantine_timestamp', 'Unknown'),
                            'file_size': report.get('file_size', 0),
                            'threat_count': len(report.get('suspicious_content', [])),
                            'threat_level': validation_result.get('threat_level', 'UNKNOWN'),
                            'extension': validation_result.get('extension', 'Unknown'),
                            'bypass_attempts': len(validation_result.get('bypass_attempts', [])),
                            'warnings': len(validation_result.get('warnings', [])),
                            'file_exists': True
                        }
                        files.append(file_info)
                        
                    except Exception as e:
                        logger.error(f"Error reading quarantine report {filename}: {e}")

        # Sort by quarantine date (newest first)
        files.sort(key=lambda x: x['quarantine_date'], reverse=True)
        
        # Pagination
        page = request.GET.get('page', 1)
        page_size = request.GET.get('page_size', 20)
        
        paginator = Paginator(files, page_size)
        page_obj = paginator.get_page(page)
        
        return Response({
            'files': list(page_obj),
            'total_count': paginator.count,
            'page_count': paginator.num_pages,
            'current_page': page_obj.number,
            'has_next': page_obj.has_next(),
            'has_previous': page_obj.has_previous()
        })
        
    except Exception as e:
        logger.error(f"Error listing quarantined files: {e}")
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_quarantine_details(request, file_id):
    """Get detailed information about a quarantined file"""
    if not is_admin_or_security_staff(request.user):
        return Response({'error': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)
    
    quarantine_dir = getattr(
        settings, 
        'FILE_QUARANTINE_DIR', 
        os.path.join(settings.MEDIA_ROOT, 'quarantine')
    )
    
    report_path = os.path.join(quarantine_dir, f"{file_id}.json")
    file_path = os.path.join(quarantine_dir, file_id)
    
    if not os.path.exists(report_path):
        return Response({'error': 'Quarantine report not found'}, status=status.HTTP_404_NOT_FOUND)
    
    try:
        with open(report_path, 'r') as f:
            report = json.load(f)
        
        # Add file existence check
        report['file_exists'] = os.path.exists(file_path)
        
        # Add file size on disk
        if report['file_exists']:
            report['file_size_on_disk'] = os.path.getsize(file_path)
        
        return Response(report)
        
    except Exception as e:
        logger.error(f"Error reading quarantine details for {file_id}: {e}")
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def restore_quarantined_file(request, file_id):
    """Restore a quarantined file to uploads directory"""
    if not is_admin_or_security_staff(request.user):
        return Response({'error': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)
    
    quarantine_dir = getattr(
        settings, 
        'FILE_QUARANTINE_DIR', 
        os.path.join(settings.MEDIA_ROOT, 'quarantine')
    )
    
    report_path = os.path.join(quarantine_dir, f"{file_id}.json")
    file_path = os.path.join(quarantine_dir, file_id)
    
    if not os.path.exists(report_path) or not os.path.exists(file_path):
        return Response({'error': 'Quarantined file not found'}, status=status.HTTP_404_NOT_FOUND)
    
    try:
        with open(report_path, 'r') as f:
            report = json.load(f)
    except Exception as e:
        return Response({'error': f'Error reading quarantine report: {e}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    original_filename = report.get('original_filename', file_id)
    validation_result = report.get('validation_result', {})
    threat_level = validation_result.get('threat_level', 'UNKNOWN')
    
    # Safety check
    force = request.data.get('force', False)
    if threat_level in ['HIGH', 'CRITICAL'] and not force:
        return Response({
            'error': f'File has {threat_level} threat level. Set force=true to restore anyway.',
            'threat_level': threat_level,
            'requires_force': True
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        # Create uploads directory if it doesn't exist
        uploads_dir = os.path.join(settings.MEDIA_ROOT, 'uploads')
        os.makedirs(uploads_dir, exist_ok=True)
        
        # Generate unique filename to avoid conflicts
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        restore_filename = f"restored_{timestamp}_{original_filename}"
        restore_path = os.path.join(uploads_dir, restore_filename)
        
        # Copy file to uploads
        shutil.copy2(file_path, restore_path)
        
        # Create restore log
        restore_log = {
            'original_quarantine_id': file_id,
            'original_filename': original_filename,
            'restored_filename': restore_filename,
            'restore_timestamp': datetime.now().isoformat(),
            'threat_level': threat_level,
            'restored_by': request.user.username,
            'user_id': request.user.id,
            'force_restore': force
        }
        
        log_path = os.path.join(uploads_dir, f"{restore_filename}.restore_log.json")
        with open(log_path, 'w') as f:
            json.dump(restore_log, f, indent=2)
        
        # Log the action
        logger.info(f"File restored by {request.user.username}: {original_filename} -> {restore_filename}")
        
        return Response({
            'message': 'File restored successfully',
            'restored_filename': restore_filename,
            'restore_path': restore_path,
            'restore_log': restore_log
        })
        
    except Exception as e:
        logger.error(f"Error restoring file {file_id}: {e}")
        return Response({'error': f'Error restoring file: {e}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_quarantined_file(request, file_id):
    """Permanently delete a quarantined file"""
    if not is_admin_or_security_staff(request.user):
        return Response({'error': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)
    
    quarantine_dir = getattr(
        settings, 
        'FILE_QUARANTINE_DIR', 
        os.path.join(settings.MEDIA_ROOT, 'quarantine')
    )
    
    report_path = os.path.join(quarantine_dir, f"{file_id}.json")
    file_path = os.path.join(quarantine_dir, file_id)
    
    if not os.path.exists(report_path):
        return Response({'error': 'Quarantine report not found'}, status=status.HTTP_404_NOT_FOUND)
    
    try:
        # Get original filename for logging
        with open(report_path, 'r') as f:
            report = json.load(f)
        original_filename = report.get('original_filename', file_id)
        
        # Delete files
        if os.path.exists(file_path):
            os.remove(file_path)
        if os.path.exists(report_path):
            os.remove(report_path)
        
        # Log the action
        logger.info(f"Quarantined file deleted by {request.user.username}: {original_filename}")
        
        return Response({
            'message': 'File deleted successfully',
            'deleted_filename': original_filename
        })
        
    except Exception as e:
        logger.error(f"Error deleting quarantined file {file_id}: {e}")
        return Response({'error': f'Error deleting file: {e}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def cleanup_old_quarantine_files(request):
    """Clean up quarantined files older than specified days"""
    if not is_admin_or_security_staff(request.user):
        return Response({'error': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)
    
    days = request.data.get('days', 30)
    force = request.data.get('force', False)
    
    quarantine_dir = getattr(
        settings, 
        'FILE_QUARANTINE_DIR', 
        os.path.join(settings.MEDIA_ROOT, 'quarantine')
    )
    
    try:
        cutoff_date = timezone.now() - timedelta(days=days)
        old_files = []
        
        for filename in os.listdir(quarantine_dir):
            if filename.endswith('.json'):
                report_path = os.path.join(quarantine_dir, filename)
                
                try:
                    with open(report_path, 'r') as f:
                        report = json.load(f)
                    
                    quarantine_date_str = report.get('quarantine_timestamp')
                    if quarantine_date_str:
                        # Parse ISO format datetime
                        quarantine_date = datetime.fromisoformat(
                            quarantine_date_str.replace('Z', '+00:00')
                        )
                        
                        if quarantine_date.replace(tzinfo=timezone.utc) < cutoff_date:
                            old_files.append({
                                'id': filename[:-5],
                                'name': report.get('original_filename', filename),
                                'date': quarantine_date_str
                            })
                
                except Exception as e:
                    logger.warning(f"Error checking file {filename}: {e}")
        
        if not old_files:
            return Response({
                'message': f'No quarantined files older than {days} days found',
                'deleted_count': 0,
                'old_files': []
            })
        
        if not force:
            return Response({
                'message': f'Found {len(old_files)} files older than {days} days',
                'old_files': old_files,
                'requires_confirmation': True
            })
        
        # Delete old files
        deleted_count = 0
        errors = []
        
        for file_info in old_files:
            try:
                file_id = file_info['id']
                report_path = os.path.join(quarantine_dir, f"{file_id}.json")
                file_path = os.path.join(quarantine_dir, file_id)
                
                if os.path.exists(file_path):
                    os.remove(file_path)
                if os.path.exists(report_path):
                    os.remove(report_path)
                
                deleted_count += 1
                
            except Exception as e:
                errors.append(f"Error deleting {file_info['name']}: {e}")
        
        # Log the cleanup
        logger.info(f"Quarantine cleanup by {request.user.username}: deleted {deleted_count} files older than {days} days")
        
        return Response({
            'message': f'Cleanup complete. Deleted {deleted_count} files.',
            'deleted_count': deleted_count,
            'errors': errors
        })
        
    except Exception as e:
        logger.error(f"Error during quarantine cleanup: {e}")
        return Response({'error': f'Cleanup failed: {e}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def quarantine_stats(request):
    """Get quarantine statistics"""
    if not is_admin_or_security_staff(request.user):
        return Response({'error': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)
    
    quarantine_dir = getattr(
        settings, 
        'FILE_QUARANTINE_DIR', 
        os.path.join(settings.MEDIA_ROOT, 'quarantine')
    )
    
    try:
        stats = get_quarantine_stats(quarantine_dir)
        return Response(stats)
        
    except Exception as e:
        logger.error(f"Error getting quarantine stats: {e}")
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


def get_quarantine_stats(quarantine_dir):
    """Helper function to calculate quarantine statistics"""
    if not os.path.exists(quarantine_dir):
        return {
            'total_files': 0,
            'total_size': 0,
            'threat_levels': {},
            'file_types': {},
            'recent_files': 0,
            'old_files': 0
        }
    
    stats = {
        'total_files': 0,
        'total_size': 0,
        'threat_levels': {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0, 'UNKNOWN': 0},
        'file_types': {},
        'recent_files': 0,  # Last 7 days
        'old_files': 0      # Older than 30 days
    }
    
    recent_cutoff = timezone.now() - timedelta(days=7)
    old_cutoff = timezone.now() - timedelta(days=30)
    
    for filename in os.listdir(quarantine_dir):
        if filename.endswith('.json'):
            report_path = os.path.join(quarantine_dir, filename)
            file_path = report_path[:-5]
            
            if os.path.exists(file_path):
                try:
                    with open(report_path, 'r') as f:
                        report = json.load(f)
                    
                    stats['total_files'] += 1
                    stats['total_size'] += report.get('file_size', 0)
                    
                    # Threat level stats
                    validation_result = report.get('validation_result', {})
                    threat_level = validation_result.get('threat_level', 'UNKNOWN')
                    stats['threat_levels'][threat_level] = stats['threat_levels'].get(threat_level, 0) + 1
                    
                    # File type stats
                    extension = validation_result.get('extension', 'unknown')
                    stats['file_types'][extension] = stats['file_types'].get(extension, 0) + 1
                    
                    # Date-based stats
                    quarantine_date_str = report.get('quarantine_timestamp')
                    if quarantine_date_str:
                        try:
                            quarantine_date = datetime.fromisoformat(
                                quarantine_date_str.replace('Z', '+00:00')
                            )
                            quarantine_date = quarantine_date.replace(tzinfo=timezone.utc)
                            
                            if quarantine_date > recent_cutoff:
                                stats['recent_files'] += 1
                            elif quarantine_date < old_cutoff:
                                stats['old_files'] += 1
                        except Exception:
                            pass
                
                except Exception as e:
                    logger.warning(f"Error processing quarantine stats for {filename}: {e}")
    
    return stats