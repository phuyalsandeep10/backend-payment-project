#!/usr/bin/env bash
# exit on error
set -o errexit

# Install dependencies
pip install -r requirements.txt

# Change to backend directory and run migrations
cd backend
python manage.py migrate