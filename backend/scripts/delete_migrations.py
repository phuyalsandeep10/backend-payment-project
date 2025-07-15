#!/usr/bin/env python
"""
Migration Cleanup Script
Deletes all migration files except __init__.py files.
WARNING: This will destroy your migration history and may cause data loss.
"""

import os
import sys
import glob
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


def show_migration_files():
    """Display all migration files that would be deleted."""
    migration_files = get_migration_files()
    
    print("📋 Migration files that would be deleted:")
    print("=" * 50)
    
    if not migration_files:
        print("✅ No migration files found to delete.")
        return []
    
    for file_path in migration_files:
        print(f"  - {file_path}")
    
    print(f"\n📊 Total: {len(migration_files)} migration files")
    return migration_files


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


def main():
    """Main function."""
    print("🗑️  Migration Cleanup Script")
    print("=" * 50)
    print("⚠️  WARNING: This script will delete all migration files!")
    print("⚠️  This will destroy your migration history.")
    print("⚠️  You may lose data if you don't handle this properly.")
    print("=" * 50)
    
    # Show what would be deleted
    migration_files = show_migration_files()
    
    if not migration_files:
        print("\n✅ No migration files to delete.")
        return
    
    # Ask for confirmation
    print("\n🤔 What would you like to do?")
    print("1. Show migration files only (no changes)")
    print("2. Create backup of migration files")
    print("3. Delete migration files (DANGEROUS)")
    print("4. Create backup AND delete migration files")
    print("5. Exit without changes")
    
    while True:
        choice = input("\nEnter your choice (1-5): ").strip()
        
        if choice == '1':
            print("✅ Showing migration files only - no changes made.")
            break
            
        elif choice == '2':
            backup_migration_files(migration_files)
            print("✅ Backup completed.")
            break
            
        elif choice == '3':
            confirm = input("🚨 Are you SURE you want to delete all migration files? (yes/no): ").strip().lower()
            if confirm == 'yes':
                deleted_count = delete_migration_files(migration_files)
                print(f"\n✅ Deleted {deleted_count} migration files.")
                print("⚠️  Remember to handle your database appropriately!")
            else:
                print("✅ Operation cancelled.")
            break
            
        elif choice == '4':
            backup_migration_files(migration_files)
            confirm = input("🚨 Are you SURE you want to delete all migration files? (yes/no): ").strip().lower()
            if confirm == 'yes':
                deleted_count = delete_migration_files(migration_files)
                print(f"\n✅ Deleted {deleted_count} migration files.")
                print("⚠️  Remember to handle your database appropriately!")
            else:
                print("✅ Operation cancelled.")
            break
            
        elif choice == '5':
            print("✅ Exiting without changes.")
            break
            
        else:
            print("❌ Invalid choice. Please enter 1-5.")


if __name__ == "__main__":
    main() 