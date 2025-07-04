#!/usr/bin/env bash
# exit on error
set -o errexit

# Run the initialization command
python backend/manage.py initialize_app

# Start the Gunicorn server
gunicorn core_config.wsgi:application --bind 0.0.0.0:$PORT 