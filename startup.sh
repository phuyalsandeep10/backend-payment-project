#!/usr/bin/env bash
# exit on error
set -o errexit

# Change to the backend directory where manage.py is located
cd backend

# Run migrations and initialization
python manage.py migrate
python manage.py initialize_app

# Start Gunicorn from the backend directory
gunicorn core_config.wsgi:application --bind 0.0.0.0:$PORT