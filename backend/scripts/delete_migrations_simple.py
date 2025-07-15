#!/usr/bin/env python
"""
Simple Migration Cleanup Script
Deletes all migration files except __init__.py files.
WARNING: This will destroy your migration history and may cause data loss.
Usage: python scripts/delete_migrations_simple.py [--backup] [--force]
"""

import os
import sys
import argparse
from pathlib import Path


def get_migration_files():
    """Get all migration files in the project."""
    migration_files = []
    
    # Get all apps directories
    apps_dirs = [
        'authentication',
        'clients', 
        'commission',
        'deals',
        'notifications',
        'organization',
        'permissions',
        'project',
        'Sales_dashboard',
        'team',
        'Verifier_dashboard'
    ]
    
    for app in apps_dirs:
        migrations_dir = Path(app) / 'migrations'
        if migrations_dir.exists():
            # Find all .py files except __init__.py
            for py_file in migrations_dir.glob('*.py'):
                if py_file.name != '__init__.py':
                    migration_files.append(py_file)
    
    return migration_files


def backup_migration_files(migration_files):
    """Create a backup of migration files."""
    backup_dir = Path('migration_backup')
    backup_dir.mkdir(exist_ok=True)
    
    print(f"📦 Creating backup in {backup_dir}...")
    
    for file_path in migration_files:
        try:
            # Create app directory in backup
            app_backup_dir = backup_dir / file_path.parent.name
            app_backup_dir.mkdir(exist_ok=True)
            
            # Copy file to backup
            backup_file = app_backup_dir / file_path.name
            with open(file_path, 'r', encoding='utf-8') as src:
                with open(backup_file, 'w', encoding='utf-8') as dst:
                    dst.write(src.read())
            
            print(f"  ✅ Backed up: {file_path}")
        except Exception as e:
            print(f"  ❌ Failed to backup {file_path}: {e}")


def delete_migration_files(migration_files):
    """Delete the specified migration files."""
    deleted_count = 0
    
    for file_path in migration_files:
        try:
            file_path.unlink()
            print(f"  ✅ Deleted: {file_path}")
            deleted_count += 1
        except Exception as e:
            print(f"  ❌ Failed to delete {file_path}: {e}")
    
    return deleted_count


def main():
    """Main function."""
    parser = argparse.ArgumentParser(description='Delete all migration files')
    parser.add_argument('--backup', action='store_true', help='Create backup before deleting')
    parser.add_argument('--force', action='store_true', help='Skip confirmation prompts')
    
    args = parser.parse_args()
    
    print("🗑️  Simple Migration Cleanup Script")
    print("=" * 50)
    print("⚠️  WARNING: This script will delete all migration files!")
    print("⚠️  This will destroy your migration history.")
    print("⚠️  You may lose data if you don't handle this properly.")
    print("=" * 50)
    
    # Get migration files
    migration_files = get_migration_files()
    
    if not migration_files:
        print("✅ No migration files found to delete.")
        return
    
    print(f"📋 Found {len(migration_files)} migration files to delete:")
    for file_path in migration_files:
        print(f"  - {file_path}")
    
    # Create backup if requested
    if args.backup:
        backup_migration_files(migration_files)
    
    # Confirm deletion
    if not args.force:
        confirm = input("\n🚨 Are you SURE you want to delete all migration files? (yes/no): ").strip().lower()
        if confirm != 'yes':
            print("✅ Operation cancelled.")
            return
    
    # Delete files
    deleted_count = delete_migration_files(migration_files)
    print(f"\n✅ Deleted {deleted_count} migration files.")
    print("⚠️  Remember to handle your database appropriately!")
    print("\n📝 Next steps:")
    print("1. Drop your database or clear django_migrations table")
    print("2. Run: python manage.py makemigrations")
    print("3. Run: python manage.py migrate")


if __name__ == "__main__":
    main() 