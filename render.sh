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

# 2. Flush DB so we always start from a clean slate.
#    Safe on Render because each deploy uses a new disk image, but we do it
#    explicitly so that re-deploys reset data too.
echo "🧹 Flushing existing data …"
python manage.py flush --noinput

# 3. Load the fixture
FIXTURE_PATH="$(pwd)/initial_data.json"
if [[ ! -f "$FIXTURE_PATH" ]]; then
  # also try sibling locations (repo root / fixtures dir)
  for p in "$(pwd)/../initial_data.json" "$(pwd)/fixtures/initial_data.json"; do
    [[ -f "$p" ]] && FIXTURE_PATH="$p" && break
  done
fi

if [[ -f "$FIXTURE_PATH" ]]; then
  echo "🌱 Loading seed data from $FIXTURE_PATH …"
  python manage.py loaddata "$FIXTURE_PATH" --verbosity 0
  echo "✅ Seed data loaded."
else
  echo "⚠️  No initial_data.json fixture found – skipping seed."
fi

# 4. Create / verify permissions & roles (project-specific custom commands)
echo "🔐 Repairing permissions and roles …"
python manage.py create_all_permissions || true
python manage.py setup_permissions || true

# 5. Collect static files for WhiteNoise / CDN
echo "📦 Collecting static files …"
python manage.py collectstatic --noinput --clear

# 6. Ensure super-admin exists (uses env-vars to avoid hard-coding secrets)
ADMIN_EMAIL=${ADMIN_EMAIL:-"superadmin@example.com"}
ADMIN_USER=${ADMIN_USER:-"superadmin"}
ADMIN_PASS=${ADMIN_PASS:-"SuperSecure123"}

python - <<PY
import os, django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_config.settings')

django.setup()
from django.contrib.auth import get_user_model
User = get_user_model()

email = os.getenv('ADMIN_EMAIL')
username = os.getenv('ADMIN_USER')
password = os.getenv('ADMIN_PASS')

user, created = User.objects.get_or_create(email=email, defaults={
    "username": username,
    "is_staff": True,
    "is_superuser": True,
})
if not created:
    print("ℹ️  Super-admin already exists – resetting password …")
else:
    print("✅ Super-admin created.")
user.set_password(password)
user.is_superuser = True
user.is_staff = True
user.save()
PY

# ---------------------------------------------------------------------------
# Launch ASGI server (Daphne) – $PORT is injected by Render
# ---------------------------------------------------------------------------

echo "🚀 Starting Daphne (ASGI) on port $PORT …"
daphne -b 0.0.0.0 -p "$PORT" core_config.asgi:application
