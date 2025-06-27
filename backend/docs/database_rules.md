✅ 1. Warning: pkg_resources is deprecated
This is not a breaking error, but a deprecation warning from drf-yasg:

bash
UserWarning: pkg_resources is deprecated as an API.
✅ Solution:
To silence or resolve this:

Either ignore it for now, it won’t block anything.

Or downgrade setuptools (temporary fix):

bash
pip install "setuptools<81"
Or wait for drf-yasg to upgrade and remove pkg_resources.

❌ 2. Error: Inconsistent Migration History
bash
django.db.migrations.exceptions.InconsistentMigrationHistory: 
Migration admin.0001_initial is applied before its dependency authentication.0001_initial on database 'default'.

This happens when the migration state in the DB is corrupted—i.e., some apps were migrated in the wrong order or manually tweaked.

✅ How to Fix InconsistentMigrationHistory
You have a few options based on how critical your DB data is.

🔧 Option 1: If you can reset your database (dev only)
If this is a development environment and you don’t mind losing DB data:

bash

# Stop server
# Delete DB (SQLite: delete db.sqlite3, PostgreSQL: drop and recreate DB)
# Delete all migration files EXCEPT __init__.py inside each app's migrations/ folder:
find . -path "*/migrations/*.py" -not -name "__init__.py" -delete
find . -path "*/migrations/*.pyc"  -delete

# Recreate fresh migrations
python manage.py makemigrations
python manage.py migrate

🩹 Option 2: If DB is production or you want to keep the data
Use the following step-by-step to fix dependency order:

Fake the missing migration dependency:

bash

python manage.py migrate authentication 0001 --fake
Then reapply the original migration:

bash

python manage.py migrate admin
Continue normal migrations:

bash

python manage.py migrate
🧠 Root Cause: What to Avoid
To prevent this issue in the future:

Always run makemigrations before migrate, and apply them in full for all apps.

Avoid applying migrations app-by-app unless you know what you're doing.

Don’t delete or manually edit migration files unless you're doing a full reset or coordinating with your team carefully.

🛡 Bonus: Safe Migration Practices
To keep migrations smooth in a team or deployment setup:

✅ Use consistent environments: pip freeze > requirements.txt

✅ Use version control for migration files

✅ Apply migrations in order:

bash

python manage.py makemigrations
python manage.py migrate

🔁 On CI/CD or staging:

bash
python manage.py showmigrations