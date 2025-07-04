#!/usr/bin/env bash
# exit on error
set -o errexit

# Start the Django server (which will auto-run setup via the modified manage.py)
python backend/manage.py runserver 0.0.0.0:$PORT