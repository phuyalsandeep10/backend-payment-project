#!/usr/bin/env bash
# exit on error
set -o errexit

# Install dependencies
pip install -r backend/requirements.txt

# Change to backend directory and run migrations
cd backend
python manage.py migrate --fake Sales_dashboard 0002_add_user_to_dailystreakrecord
python manage.py migrate --fake Verifier_dashboard 0002_add_organization_and_user_to_auditlogs
python manage.py migrate --fake authentication 0003_add_role_and_user_permissions
python manage.py migrate