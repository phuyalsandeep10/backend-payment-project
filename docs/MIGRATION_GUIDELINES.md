# Migration Guidelines

## 🚨 Critical Rules

### 1. **Never Commit Unapplied Migrations**
- Always run `python manage.py migrate` locally before committing
- Use `python manage.py check_migration_safety` to verify

### 2. **Test Migrations Before Deployment**
- Run `python scripts/test_migrations.py` before pushing
- Test on a copy of production data if possible

### 3. **Migration Naming Convention**
- Use descriptive names: `add_user_profile_bio_field`
- Include app name: `authentication_0004_add_user_profile_bio_field`

## 🔧 Development Workflow

### Before Making Model Changes:
```bash
# 1. Check current migration state
python manage.py showmigrations

# 2. Make your model changes

# 3. Create migrations
python manage.py makemigrations

# 4. Test migrations
python manage.py migrate --plan

# 5. Apply migrations
python manage.py migrate

# 6. Verify
python manage.py check_migration_safety
```

### Before Committing:
```bash
# 1. Run safety checks
python manage.py check_migration_safety --dry-run

# 2. Test the application
python manage.py runserver
# Test your changes manually

# 3. Commit only if everything works
git add .
git commit -m "Add user profile bio field with migration"
```

## 🚀 Deployment Safety

### Pre-deployment Checklist:
- [ ] All migrations are applied locally
- [ ] Migration safety check passes
- [ ] Application starts without errors
- [ ] Database connectivity works
- [ ] No pending migrations in production

### Emergency Rollback:
```bash
# If migration fails in production:
python manage.py migrate --fake <app_name> <previous_migration>
```

## ⚠️ Common Pitfalls

### 1. **Field Type Changes**
- Be careful when changing field types
- Consider data migration scripts for complex changes

### 2. **Required Fields**
- Add `null=True, blank=True` initially
- Migrate data, then make required

### 3. **Foreign Key Changes**
- Test relationships thoroughly
- Use `on_delete` appropriately

### 4. **Index Changes**
- Test performance impact
- Consider downtime for large tables

## 🛠️ Tools and Commands

### Migration Safety Commands:
```bash
# Check migration safety
python manage.py check_migration_safety

# Test migrations on temporary database
python scripts/test_migrations.py

# Show migration plan
python manage.py migrate --plan

# Fake migrations (use carefully)
python manage.py migrate --fake <app_name> <migration_name>
```

### Debugging Commands:
```bash
# Show all migrations
python manage.py showmigrations

# Show specific app migrations
python manage.py showmigrations <app_name>

# Check for conflicts
python manage.py makemigrations --dry-run
```

## 📋 Migration Checklist

### For Each Migration:
- [ ] Descriptive name
- [ ] Tests pass
- [ ] Application starts
- [ ] Data integrity maintained
- [ ] Performance impact assessed
- [ ] Rollback plan ready

### For Deployment:
- [ ] Migration safety check passes
- [ ] Backup created
- [ ] Maintenance window scheduled
- [ ] Rollback procedure documented
- [ ] Team notified

## 🆘 Emergency Procedures

### If Migration Fails in Production:
1. **Stop the deployment immediately**
2. **Assess the damage**
3. **Restore from backup if necessary**
4. **Fix the migration locally**
5. **Test thoroughly**
6. **Redeploy with fixed migration**

### Contact Information:
- **Lead Developer**: [Your Name]
- **Database Admin**: [DBA Name]
- **Emergency Hotline**: [Phone Number] 