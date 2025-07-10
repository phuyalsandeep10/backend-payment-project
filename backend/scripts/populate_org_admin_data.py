#!/usr/bin/env python
"""
Populate Org-Admin Demo Data
===========================
Convenience script that chains all the individual seed commands so the full
Org-Admin dashboard has realistic information straight after a fresh setup.

What it does:
1. Ensures default demo roles / projects / users / teams via `seed_demo_data`.
2. Creates an assorted client list via `seed_clients` (50 by default).
3. Generates deals and payments for those clients via `seed_deals_data`.
4. Runs the rich `initialize_app` command to add commissions, notifications, etc.

The script is *idempotent* – running it multiple times will not create duplicates.

Usage:
    ./populate_org_admin_data.py   # from repo root (make sure venv + DJANGO_SETTINGS_MODULE) 

You can also execute with Python:
    python backend/Backend_PRS/backend/scripts/populate_org_admin_data.py
"""

import os
import sys
from pathlib import Path

import django
from django.core.management import call_command


BACKEND_DIR = Path(__file__).resolve().parents[1]  # /backend/Backend_PRS/backend


def setup_django():
    """Configure settings and initialise Django"""
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core_config.settings")
    # Ensure backend package dir (contains core_config) is on PYTHONPATH
    sys.path.insert(0, str(BACKEND_DIR))
    django.setup()


def main():
    setup_django()

    print("🚀 Populating Org-Admin demo data …\n")

    # 1. Core demo data – org, roles, users, teams, projects
    print("➡️  Running seed_demo_data …")
    call_command("seed_demo_data")

    # 2. Clients
    print("➡️  Seeding 50 demo clients …")
    call_command("seed_clients", count=50)

    # 3. Deals & payments for those clients
    print("➡️  Generating deals & payments …")
    call_command("seed_deals_data")

    # 4. Rich dataset (commissions, notifications, etc.)
    print("➡️  Initialising extended mock data …")
    call_command("initialize_app")

    print("✅ All demo data populated. Log in as Org-Admin to see populated tables!")


if __name__ == "__main__":
    main() 