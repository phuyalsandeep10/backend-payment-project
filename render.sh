#!/usr/bin/env bash
# ----------------------------------------------------------------------------
# Render Start Script for PRS Backend (Django + Channels)
# This script is executed as the *Start Command* on Render.
# It performs the full boot-strap process:
#   1. Wait for Postgres to be available
#   2. Run database migrations
#   3. Flush the database so it is empty on every deploy
#   4. Seed data from `initial_data.json`
#   5. Create/repair permissions and roles
#   6. Collect static files
#   7. Ensure the super-admin account exists / password is updated
#   8. Launch the ASGI server with Daphne (WebSockets ready)
# ----------------------------------------------------------------------------
set -o errexit
set -o pipefail

# Helper: simple wait loop for Postgres when DATABASE_URL is provided.
wait_for_db() {
  if [[ -z "$DATABASE_URL" ]]; then
    return 0
  fi
  echo "⏳ Waiting for database to be ready …"
  python - <<'PY'
import os, time, sys
import psycopg

dsn = os.environ["DATABASE_URL"]
for _ in range(30):
    try:
        with psycopg.connect(dsn, connect_timeout=3):
            print("✅ Database is available.")
            sys.exit(0)
    except Exception as exc:
        print("Database not ready – sleeping 2 s", exc)
        time.sleep(2)
print("❌ Database never became ready – exiting.")
sys.exit(1)
PY
}

wait_for_db

# ---------------------------------------------------------------------------
# Django management tasks
# ---------------------------------------------------------------------------
cd backend

# 1. Apply migrations
echo "🔄 Applying database migrations …"
python manage.py migrate --noinput

# 2. Collect static files
echo "📦 Collecting static files …"
python manage.py collectstatic --noinput --clear

# 3. Initialize app: flush, create orgs, roles, assign permissions, superadmin, etc.
echo "🚀 Initializing app (roles, permissions, orgs, superadmin, etc.) …"
python manage.py initialize_app --flush

# 4. (Optional) Fix deployment permissions (if needed)
python manage.py fix_deployment_permissions || true

# 5. Launch ASGI server (Daphne)
echo "🚀 Starting Daphne (ASGI) on port $PORT …"
daphne -b 0.0.0.0 -p "$PORT" core_config.asgi:application

# End of script
