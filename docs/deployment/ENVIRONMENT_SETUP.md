# Environment Setup Guide

## Overview

This guide provides comprehensive instructions for setting up the Payment Receiving System (PRS) Backend across different environments: Development, Staging, and Production. Each environment has specific configurations optimized for its purpose.

---

## 📋 Table of Contents

1. [Environment Overview](#environment-overview)
2. [Development Environment](#development-environment)
3. [Staging Environment](#staging-environment)
4. [Production Environment](#production-environment)
5. [Environment Variables](#environment-variables)
6. [Database Configuration](#database-configuration)
7. [Infrastructure as Code](#infrastructure-as-code)
8. [Environment Promotion](#environment-promotion)

---

## 🌍 Environment Overview

### Environment Characteristics

| Environment | Purpose | Data | Performance | Security | Monitoring |
|------------|---------|------|-------------|----------|------------|
| **Development** | Local development and testing | Synthetic/Sample | Basic | Relaxed | Minimal |
| **Staging** | Pre-production testing | Production-like | Medium | Enhanced | Full |
| **Production** | Live application | Real | High | Maximum | Comprehensive |

### Common Infrastructure Components

```mermaid
graph TB
    Dev[Development Environment]
    Staging[Staging Environment]
    Prod[Production Environment]
    
    Dev --> |Code Promotion| Staging
    Staging --> |Validated Release| Prod
    
    Dev --> LocalDB[Local PostgreSQL]
    Dev --> LocalRedis[Local Redis]
    
    Staging --> StagingDB[Staging PostgreSQL]
    Staging --> StagingRedis[Staging Redis]
    Staging --> StagingS3[Staging S3]
    
    Prod --> ProdDB[Production PostgreSQL<br/>Multi-AZ]
    Prod --> ProdRedis[Production Redis<br/>Cluster]
    Prod --> ProdS3[Production S3<br/>CDN]
    Prod --> Monitoring[CloudWatch/DataDog]
```

---

## 💻 Development Environment

### Local Development Setup

#### Prerequisites

```bash
# System requirements
python --version  # Python 3.9+
node --version    # Node.js 16+
git --version     # Git 2.25+
docker --version  # Docker 20+

# Database requirements
psql --version    # PostgreSQL 12+
redis-cli --version  # Redis 6+
```

#### 1. Initial Setup

```bash
#!/bin/bash
# setup-development.sh

set -e

echo "🚀 Setting up PRS Development Environment"

# Clone repository (if not already done)
# git clone https://github.com/your-org/prs-backend.git
cd Backend_PRS

# Create Python virtual environment
echo "📦 Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements/development.txt

# Create development environment file
echo "⚙️ Creating development environment configuration..."
cat > backend/.env.development << 'EOF'
# Django Core Settings
SECRET_KEY=django-insecure-dev-key-change-in-production
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1,0.0.0.0
DJANGO_SETTINGS_MODULE=core_config.settings.development

# Database Configuration (Local PostgreSQL)
DATABASE_URL=postgresql://prs_dev:devpassword@localhost:5432/prs_development
DB_NAME=prs_development
DB_USER=prs_dev
DB_PASSWORD=devpassword
DB_HOST=localhost
DB_PORT=5432

# Cache Configuration (Local Redis)
REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/1

# Email Configuration (Development - Console backend)
EMAIL_BACKEND=django.core.mail.backends.console.EmailBackend
DEFAULT_FROM_EMAIL=dev@prs.local
SUPER_ADMIN_OTP_EMAIL=admin@prs.local

# Media Storage (Local filesystem)
USE_S3=False
MEDIA_ROOT=/tmp/prs_media
STATIC_ROOT=/tmp/prs_static

# Development Settings
LOG_LEVEL=DEBUG
ENABLE_MONITORING=False
ENABLE_DEBUG_TOOLBAR=True

# API Settings
API_BASE_URL=http://localhost:8000/api
FRONTEND_URL=http://localhost:3000
CORS_ALLOW_ALL_ORIGINS=True

# Performance (Development)
GUNICORN_WORKERS=2
GUNICORN_THREADS=1
DATABASE_CONN_MAX_AGE=0
EOF

echo "✅ Development environment configuration created"
```

#### 2. Database Setup

```bash
#!/bin/bash
# setup-dev-database.sh

set -e

echo "🗄️ Setting up development database..."

# Check if PostgreSQL is running
pg_isready || {
    echo "❌ PostgreSQL is not running"
    echo "💡 Start PostgreSQL: brew services start postgresql (macOS)"
    echo "💡 Start PostgreSQL: sudo service postgresql start (Linux)"
    exit 1
}

# Create database user
echo "👤 Creating database user..."
psql -c "CREATE USER prs_dev WITH PASSWORD 'devpassword';" || echo "User already exists"
psql -c "ALTER USER prs_dev CREATEDB;" || echo "Permission already granted"

# Create development database
echo "🏗️ Creating development database..."
psql -c "CREATE DATABASE prs_development OWNER prs_dev;" || echo "Database already exists"

# Create test database
psql -c "CREATE DATABASE prs_test OWNER prs_dev;" || echo "Test database already exists"

# Grant permissions
psql -d prs_development -c "GRANT ALL PRIVILEGES ON SCHEMA public TO prs_dev;"
psql -d prs_test -c "GRANT ALL PRIVILEGES ON SCHEMA public TO prs_dev;"

# Create extensions
psql -d prs_development -c "CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";"
psql -d prs_development -c "CREATE EXTENSION IF NOT EXISTS \"pg_trgm\";"
psql -d prs_development -c "CREATE EXTENSION IF NOT EXISTS \"btree_gin\";"

echo "✅ Development database setup completed"
```

#### 3. Application Startup

```bash
#!/bin/bash
# start-development.sh

set -e

echo "🚀 Starting PRS Development Server..."

# Activate virtual environment
source venv/bin/activate

# Load environment variables
cd backend
export $(cat .env.development | grep -v ^# | xargs)

# Run migrations
echo "🔄 Running migrations..."
python manage.py migrate

# Create superuser if doesn't exist
echo "👤 Creating superuser..."
python manage.py shell << 'EOF'
from django.contrib.auth import get_user_model
User = get_user_model()
if not User.objects.filter(email='admin@prs.local').exists():
    User.objects.create_superuser(
        email='admin@prs.local',
        password='admin123',
        first_name='Dev',
        last_name='Admin'
    )
    print("✅ Superuser created: admin@prs.local / admin123")
else:
    print("✅ Superuser already exists")
EOF

# Load sample data
echo "📊 Loading sample data..."
python manage.py loaddata fixtures/development_data.json || echo "No fixture file found"

# Start Celery worker in background
echo "🔄 Starting Celery worker..."
celery -A core_config worker --loglevel=info --detach

# Start Celery beat in background
echo "⏰ Starting Celery beat..."
celery -A core_config beat --loglevel=info --detach

# Start Django development server
echo "🌐 Starting Django development server..."
python manage.py runserver 0.0.0.0:8000
```

#### 4. Docker Development Setup

```yaml
# docker-compose.development.yml
version: '3.8'

services:
  app:
    build:
      context: .
      dockerfile: docker/Dockerfile.development
    volumes:
      - .:/app
      - dev_static:/app/staticfiles
      - dev_media:/app/media
    ports:
      - "8000:8000"
    environment:
      - DJANGO_SETTINGS_MODULE=core_config.settings.development
    env_file:
      - backend/.env.development
    depends_on:
      - db
      - redis
    command: ["python", "manage.py", "runserver", "0.0.0.0:8000"]

  db:
    image: postgres:14-alpine
    environment:
      POSTGRES_DB: prs_development
      POSTGRES_USER: prs_dev
      POSTGRES_PASSWORD: devpassword
    volumes:
      - dev_postgres_data:/var/lib/postgresql/data
      - ./database/init.sql:/docker-entrypoint-initdb.d/init.sql
    ports:
      - "5432:5432"

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - dev_redis_data:/data

  celery_worker:
    build:
      context: .
      dockerfile: docker/Dockerfile.development
    volumes:
      - .:/app
    environment:
      - DJANGO_SETTINGS_MODULE=core_config.settings.development
    env_file:
      - backend/.env.development
    depends_on:
      - db
      - redis
    command: ["celery", "-A", "core_config", "worker", "-l", "info"]

  celery_beat:
    build:
      context: .
      dockerfile: docker/Dockerfile.development
    volumes:
      - .:/app
    environment:
      - DJANGO_SETTINGS_MODULE=core_config.settings.development
    env_file:
      - backend/.env.development
    depends_on:
      - db
      - redis
    command: ["celery", "-A", "core_config", "beat", "-l", "info"]

volumes:
  dev_postgres_data:
  dev_redis_data:
  dev_static:
  dev_media:
```

#### Development Docker Commands

```bash
# Start development environment
docker-compose -f docker-compose.development.yml up -d

# View logs
docker-compose -f docker-compose.development.yml logs -f app

# Run migrations
docker-compose -f docker-compose.development.yml exec app python manage.py migrate

# Create superuser
docker-compose -f docker-compose.development.yml exec app python manage.py createsuperuser

# Run tests
docker-compose -f docker-compose.development.yml exec app python manage.py test

# Access shell
docker-compose -f docker-compose.development.yml exec app python manage.py shell

# Stop environment
docker-compose -f docker-compose.development.yml down
```

---

## 🧪 Staging Environment

### Staging Infrastructure Setup

#### 1. AWS Staging Environment

```bash
#!/bin/bash
# setup-staging-infrastructure.sh

set -e

echo "🏗️ Setting up AWS Staging Infrastructure..."

# Variables
REGION="us-east-1"
VPC_CIDR="10.1.0.0/16"
PUBLIC_SUBNET_CIDR="10.1.1.0/24"
PRIVATE_SUBNET_CIDR="10.1.2.0/24"

# Create VPC
VPC_ID=$(aws ec2 create-vpc --cidr-block $VPC_CIDR \
    --tag-specifications 'ResourceType=vpc,Tags=[{Key=Name,Value=prs-staging-vpc},{Key=Environment,Value=staging}]' \
    --query 'Vpc.VpcId' --output text)
echo "✅ VPC created: $VPC_ID"

# Enable DNS hostnames
aws ec2 modify-vpc-attribute --vpc-id $VPC_ID --enable-dns-hostnames

# Create Internet Gateway
IGW_ID=$(aws ec2 create-internet-gateway \
    --tag-specifications 'ResourceType=internet-gateway,Tags=[{Key=Name,Value=prs-staging-igw}]' \
    --query 'InternetGateway.InternetGatewayId' --output text)
aws ec2 attach-internet-gateway --vpc-id $VPC_ID --internet-gateway-id $IGW_ID
echo "✅ Internet Gateway created: $IGW_ID"

# Create public subnet
PUBLIC_SUBNET_ID=$(aws ec2 create-subnet --vpc-id $VPC_ID \
    --cidr-block $PUBLIC_SUBNET_CIDR \
    --availability-zone ${REGION}a \
    --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=prs-staging-public}]' \
    --query 'Subnet.SubnetId' --output text)
echo "✅ Public subnet created: $PUBLIC_SUBNET_ID"

# Create private subnet
PRIVATE_SUBNET_ID=$(aws ec2 create-subnet --vpc-id $VPC_ID \
    --cidr-block $PRIVATE_SUBNET_CIDR \
    --availability-zone ${REGION}b \
    --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=prs-staging-private}]' \
    --query 'Subnet.SubnetId' --output text)
echo "✅ Private subnet created: $PRIVATE_SUBNET_ID"

# Create route table for public subnet
PUBLIC_RT_ID=$(aws ec2 create-route-table --vpc-id $VPC_ID \
    --tag-specifications 'ResourceType=route-table,Tags=[{Key=Name,Value=prs-staging-public-rt}]' \
    --query 'RouteTable.RouteTableId' --output text)
aws ec2 create-route --route-table-id $PUBLIC_RT_ID \
    --destination-cidr-block 0.0.0.0/0 --gateway-id $IGW_ID
aws ec2 associate-route-table --subnet-id $PUBLIC_SUBNET_ID --route-table-id $PUBLIC_RT_ID
echo "✅ Public route table created: $PUBLIC_RT_ID"

# Create security groups
WEB_SG_ID=$(aws ec2 create-security-group \
    --group-name prs-staging-web-sg \
    --description "PRS Staging Web Security Group" \
    --vpc-id $VPC_ID \
    --tag-specifications 'ResourceType=security-group,Tags=[{Key=Name,Value=prs-staging-web-sg}]' \
    --query 'GroupId' --output text)

# Allow HTTP, HTTPS, and SSH
aws ec2 authorize-security-group-ingress --group-id $WEB_SG_ID \
    --protocol tcp --port 80 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --group-id $WEB_SG_ID \
    --protocol tcp --port 443 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --group-id $WEB_SG_ID \
    --protocol tcp --port 22 --cidr 0.0.0.0/0
echo "✅ Web security group created: $WEB_SG_ID"

# Create database security group
DB_SG_ID=$(aws ec2 create-security-group \
    --group-name prs-staging-db-sg \
    --description "PRS Staging Database Security Group" \
    --vpc-id $VPC_ID \
    --tag-specifications 'ResourceType=security-group,Tags=[{Key=Name,Value=prs-staging-db-sg}]' \
    --query 'GroupId' --output text)

# Allow PostgreSQL access from web security group
aws ec2 authorize-security-group-ingress --group-id $DB_SG_ID \
    --protocol tcp --port 5432 --source-group $WEB_SG_ID
echo "✅ Database security group created: $DB_SG_ID"

echo "🎉 AWS Staging Infrastructure setup completed!"
echo "📝 Save these values for your deployment:"
echo "VPC_ID=$VPC_ID"
echo "PUBLIC_SUBNET_ID=$PUBLIC_SUBNET_ID"
echo "PRIVATE_SUBNET_ID=$PRIVATE_SUBNET_ID"
echo "WEB_SG_ID=$WEB_SG_ID"
echo "DB_SG_ID=$DB_SG_ID"
```

#### 2. Staging Database Setup

```bash
#!/bin/bash
# setup-staging-database.sh

set -e

# Configuration
DB_INSTANCE_ID="prs-staging-db"
DB_CLASS="db.t3.medium"
DB_ENGINE="postgres"
DB_VERSION="14.9"
DB_NAME="prs_staging"
DB_USER="prs_staging_admin"
DB_PASSWORD="staging_secure_password_$(openssl rand -hex 8)"

echo "🗄️ Setting up RDS PostgreSQL for staging..."

# Create DB subnet group
aws rds create-db-subnet-group \
    --db-subnet-group-name prs-staging-db-subnet \
    --db-subnet-group-description "PRS Staging DB Subnet Group" \
    --subnet-ids $PRIVATE_SUBNET_ID $PUBLIC_SUBNET_ID \
    --tags Key=Environment,Value=staging

# Create parameter group
aws rds create-db-parameter-group \
    --db-parameter-group-name prs-staging-params \
    --db-parameter-group-family postgres14 \
    --description "PRS Staging PostgreSQL Parameters"

# Create RDS instance
aws rds create-db-instance \
    --db-instance-identifier $DB_INSTANCE_ID \
    --db-instance-class $DB_CLASS \
    --engine $DB_ENGINE \
    --engine-version $DB_VERSION \
    --master-username $DB_USER \
    --master-user-password $DB_PASSWORD \
    --allocated-storage 50 \
    --storage-type gp2 \
    --storage-encrypted \
    --vpc-security-group-ids $DB_SG_ID \
    --db-subnet-group-name prs-staging-db-subnet \
    --db-parameter-group-name prs-staging-params \
    --backup-retention-period 7 \
    --auto-minor-version-upgrade \
    --deletion-protection \
    --tags Key=Environment,Value=staging

echo "⏳ Waiting for RDS instance to be available..."
aws rds wait db-instance-available --db-instance-identifier $DB_INSTANCE_ID

# Get RDS endpoint
DB_ENDPOINT=$(aws rds describe-db-instances \
    --db-instance-identifier $DB_INSTANCE_ID \
    --query 'DBInstances[0].Endpoint.Address' \
    --output text)

echo "✅ RDS PostgreSQL created successfully!"
echo "📝 Database connection details:"
echo "DB_HOST=$DB_ENDPOINT"
echo "DB_NAME=$DB_NAME"
echo "DB_USER=$DB_USER"
echo "DB_PASSWORD=$DB_PASSWORD"

# Store credentials in AWS Secrets Manager
aws secretsmanager create-secret \
    --name "prs/staging/database" \
    --description "PRS Staging Database Credentials" \
    --secret-string "{
        \"username\": \"$DB_USER\",
        \"password\": \"$DB_PASSWORD\",
        \"host\": \"$DB_ENDPOINT\",
        \"port\": 5432,
        \"database\": \"$DB_NAME\"
    }" \
    --tags '[{"Key":"Environment","Value":"staging"}]'

echo "🔐 Database credentials stored in AWS Secrets Manager"
```

#### 3. Staging Environment Configuration

```bash
# .env.staging
# Django Core Settings
SECRET_KEY=staging-secret-key-256-bit-random-string
DEBUG=False
ALLOWED_HOSTS=staging.yourdomain.com,staging-api.yourdomain.com
DJANGO_SETTINGS_MODULE=core_config.settings.staging

# Database Configuration
DATABASE_URL=postgresql://prs_staging_admin:password@prs-staging-db.xyz.us-east-1.rds.amazonaws.com:5432/prs_staging
DB_NAME=prs_staging
DB_USER=prs_staging_admin
DB_PASSWORD=staging_secure_password
DB_HOST=prs-staging-db.xyz.us-east-1.rds.amazonaws.com
DB_PORT=5432
DB_SSL_REQUIRE=True

# Redis Configuration
REDIS_URL=redis://prs-staging-cache.xyz.cache.amazonaws.com:6379/0
CELERY_BROKER_URL=redis://prs-staging-cache.xyz.cache.amazonaws.com:6379/0
CELERY_RESULT_BACKEND=redis://prs-staging-cache.xyz.cache.amazonaws.com:6379/1

# Email Configuration
EMAIL_HOST=smtp.gmail.com
EMAIL_HOST_USER=staging@yourdomain.com
EMAIL_HOST_PASSWORD=staging-email-password
EMAIL_PORT=587
EMAIL_USE_TLS=True
DEFAULT_FROM_EMAIL=staging@yourdomain.com
SUPER_ADMIN_OTP_EMAIL=staging-admin@yourdomain.com

# Media Storage
AWS_ACCESS_KEY_ID=your-staging-access-key
AWS_SECRET_ACCESS_KEY=your-staging-secret-key
AWS_STORAGE_BUCKET_NAME=prs-staging-media
AWS_S3_REGION_NAME=us-east-1
USE_S3=True

# Security Settings (Staging)
SECURE_PROXY_SSL_HEADER_HTTP_X_FORWARDED_PROTO=https
SECURE_SSL_REDIRECT=True
SESSION_COOKIE_SECURE=True
CSRF_COOKIE_SECURE=True

# Monitoring
SENTRY_DSN=https://your-staging-sentry-dsn@sentry.io/project-id
LOG_LEVEL=INFO
ENABLE_MONITORING=True

# Performance (Staging)
GUNICORN_WORKERS=2
GUNICORN_THREADS=2
GUNICORN_TIMEOUT=120

# Application Settings
SITE_URL=https://staging.yourdomain.com
API_BASE_URL=https://staging-api.yourdomain.com
FRONTEND_URL=https://staging-app.yourdomain.com

# Feature Flags (Staging)
ENABLE_DEBUG_TOOLBAR=False
ENABLE_SILK_PROFILER=True
ENABLE_RATE_LIMITING=True
```

#### 4. Staging Deployment Script

```bash
#!/bin/bash
# deploy-staging.sh

set -e

echo "🚀 Deploying to Staging Environment"

# Configuration
REGISTRY="your-registry.com"
IMAGE_NAME="prs-backend"
VERSION=${1:-$(git rev-parse --short HEAD)}
STAGING_HOST="staging.yourdomain.com"

# Build and push image
echo "🔨 Building staging image..."
docker build -t $REGISTRY/$IMAGE_NAME:$VERSION .
docker tag $REGISTRY/$IMAGE_NAME:$VERSION $REGISTRY/$IMAGE_NAME:staging-latest
docker push $REGISTRY/$IMAGE_NAME:$VERSION
docker push $REGISTRY/$IMAGE_NAME:staging-latest

# Deploy to staging server
echo "📤 Deploying to staging server..."
ssh deploy@$STAGING_HOST << EOF
    set -e
    
    cd /opt/prs-backend
    
    # Pull latest image
    docker pull $REGISTRY/$IMAGE_NAME:$VERSION
    
    # Update docker-compose to use new image
    sed -i 's|image: .*|image: $REGISTRY/$IMAGE_NAME:$VERSION|g' docker-compose.staging.yml
    
    # Run database migrations
    docker-compose -f docker-compose.staging.yml run --rm app python manage.py migrate
    
    # Collect static files
    docker-compose -f docker-compose.staging.yml run --rm app python manage.py collectstatic --noinput
    
    # Deploy with zero downtime
    docker-compose -f docker-compose.staging.yml up -d
    
    # Wait for health check
    sleep 30
    
    # Verify deployment
    curl -f https://staging-api.yourdomain.com/api/health/ || exit 1
    
    echo "✅ Staging deployment completed successfully"
EOF

# Run smoke tests
echo "🧪 Running smoke tests..."
./scripts/test-staging.sh https://staging-api.yourdomain.com

echo "🎉 Staging deployment completed successfully!"
```

---

## 🏭 Production Environment

### Production Infrastructure Setup

#### 1. AWS Production Environment (Terraform)

```hcl
# infrastructure/terraform/production/main.tf
terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  
  backend "s3" {
    bucket = "prs-terraform-state"
    key    = "production/terraform.tfstate"
    region = "us-east-1"
  }
}

provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Environment = "production"
      Project     = "prs-backend"
      ManagedBy   = "terraform"
    }
  }
}

# Variables
variable "aws_region" {
  description = "AWS region"
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  default     = "production"
}

variable "domain_name" {
  description = "Domain name for the application"
  default     = "yourdomain.com"
}

# VPC
module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
  version = "~> 3.0"

  name = "prs-production"
  cidr = "10.0.0.0/16"

  azs             = ["${var.aws_region}a", "${var.aws_region}b", "${var.aws_region}c"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]

  enable_nat_gateway = true
  enable_vpn_gateway = true
  enable_dns_hostnames = true
  enable_dns_support = true

  tags = {
    Environment = var.environment
  }
}

# RDS Subnet Group
resource "aws_db_subnet_group" "main" {
  name       = "prs-production-db-subnet"
  subnet_ids = module.vpc.private_subnets

  tags = {
    Name = "prs-production-db-subnet"
  }
}

# RDS Parameter Group
resource "aws_db_parameter_group" "main" {
  family = "postgres14"
  name   = "prs-production-params"

  parameter {
    name  = "log_statement"
    value = "all"
  }

  parameter {
    name  = "log_min_duration_statement"
    value = "2000"
  }
}

# RDS Instance
resource "aws_db_instance" "main" {
  identifier = "prs-production"

  # Engine
  engine         = "postgres"
  engine_version = "14.9"
  instance_class = "db.r6g.xlarge"

  # Storage
  allocated_storage     = 500
  max_allocated_storage = 1000
  storage_encrypted     = true
  storage_type          = "gp3"

  # Database
  db_name  = "prs_production"
  username = "prs_admin"
  password = random_password.db_password.result

  # Network & Security
  vpc_security_group_ids = [aws_security_group.database.id]
  db_subnet_group_name   = aws_db_subnet_group.main.name
  parameter_group_name   = aws_db_parameter_group.main.name

  # Backup & Maintenance
  backup_retention_period = 30
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:04:00-sun:05:00"
  delete_automated_backups = false
  deletion_protection    = true

  # Monitoring
  monitoring_interval = 60
  monitoring_role_arn = aws_iam_role.rds_monitoring.arn
  enabled_cloudwatch_logs_exports = ["postgresql"]

  # Performance Insights
  performance_insights_enabled = true
  performance_insights_retention_period = 7

  skip_final_snapshot = false
  final_snapshot_identifier = "prs-production-final-snapshot-${formatdate("YYYY-MM-DD-hhmm", timestamp())}"

  tags = {
    Name = "prs-production"
  }
}

# ElastiCache Subnet Group
resource "aws_elasticache_subnet_group" "main" {
  name       = "prs-production-cache-subnet"
  subnet_ids = module.vpc.private_subnets
}

# ElastiCache Replication Group
resource "aws_elasticache_replication_group" "main" {
  replication_group_id       = "prs-production-cache"
  description                = "PRS Production Redis Cluster"

  # Configuration
  node_type            = "cache.r6g.large"
  port                 = 6379
  parameter_group_name = "default.redis7"

  # Cluster
  num_cache_clusters         = 2
  automatic_failover_enabled = true
  multi_az_enabled          = true

  # Network & Security
  subnet_group_name  = aws_elasticache_subnet_group.main.name
  security_group_ids = [aws_security_group.cache.id]

  # Backup
  snapshot_retention_limit = 7
  snapshot_window         = "03:00-05:00"

  # Encryption
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token                = random_password.redis_password.result

  tags = {
    Name = "prs-production-cache"
  }
}

# Random passwords
resource "random_password" "db_password" {
  length  = 32
  special = true
}

resource "random_password" "redis_password" {
  length  = 32
  special = false
}

# Secrets Manager
resource "aws_secretsmanager_secret" "db_credentials" {
  name                    = "prs/production/database"
  description            = "PRS Production Database Credentials"
  recovery_window_in_days = 7

  tags = {
    Environment = var.environment
  }
}

resource "aws_secretsmanager_secret_version" "db_credentials" {
  secret_id = aws_secretsmanager_secret.db_credentials.id
  secret_string = jsonencode({
    username = aws_db_instance.main.username
    password = aws_db_instance.main.password
    host     = aws_db_instance.main.endpoint
    port     = aws_db_instance.main.port
    database = aws_db_instance.main.db_name
  })
}

# S3 Bucket for Media Files
resource "aws_s3_bucket" "media" {
  bucket = "prs-production-media-${random_id.bucket_suffix.hex}"
}

resource "aws_s3_bucket_versioning" "media" {
  bucket = aws_s3_bucket.media.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "media" {
  bucket = aws_s3_bucket.media.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "media" {
  bucket = aws_s3_bucket.media.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "random_id" "bucket_suffix" {
  byte_length = 8
}

# Security Groups
resource "aws_security_group" "application" {
  name        = "prs-production-app"
  description = "Security group for PRS application servers"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    security_groups = [aws_security_group.load_balancer.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "prs-production-app"
  }
}

resource "aws_security_group" "database" {
  name        = "prs-production-db"
  description = "Security group for PRS database"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.application.id]
  }

  tags = {
    Name = "prs-production-db"
  }
}

resource "aws_security_group" "cache" {
  name        = "prs-production-cache"
  description = "Security group for PRS cache"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.application.id]
  }

  tags = {
    Name = "prs-production-cache"
  }
}

resource "aws_security_group" "load_balancer" {
  name        = "prs-production-lb"
  description = "Security group for PRS load balancer"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "prs-production-lb"
  }
}

# Application Load Balancer
resource "aws_lb" "main" {
  name               = "prs-production-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.load_balancer.id]
  subnets            = module.vpc.public_subnets

  enable_deletion_protection = true

  tags = {
    Name = "prs-production-alb"
  }
}

# Outputs
output "database_endpoint" {
  value = aws_db_instance.main.endpoint
}

output "redis_endpoint" {
  value = aws_elasticache_replication_group.main.configuration_endpoint_address
}

output "s3_bucket_name" {
  value = aws_s3_bucket.media.bucket
}

output "vpc_id" {
  value = module.vpc.vpc_id
}

output "private_subnets" {
  value = module.vpc.private_subnets
}

output "public_subnets" {
  value = module.vpc.public_subnets
}
```

#### 2. Production Environment Variables

```bash
# .env.production
# Django Core Settings
SECRET_KEY=${DJANGO_SECRET_KEY}
DEBUG=False
ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com,api.yourdomain.com
DJANGO_SETTINGS_MODULE=core_config.settings.production

# Database Configuration
DATABASE_URL=${DATABASE_URL}
DB_NAME=${DB_NAME}
DB_USER=${DB_USER}
DB_PASSWORD=${DB_PASSWORD}
DB_HOST=${DB_HOST}
DB_PORT=5432
DB_SSL_REQUIRE=True

# Cache Configuration
REDIS_URL=${REDIS_URL}
REDIS_PASSWORD=${REDIS_PASSWORD}
CELERY_BROKER_URL=${CELERY_BROKER_URL}
CELERY_RESULT_BACKEND=${CELERY_RESULT_BACKEND}

# Email Configuration
EMAIL_HOST=smtp.gmail.com
EMAIL_HOST_USER=${EMAIL_HOST_USER}
EMAIL_HOST_PASSWORD=${EMAIL_HOST_PASSWORD}
EMAIL_PORT=587
EMAIL_USE_TLS=True
DEFAULT_FROM_EMAIL=${DEFAULT_FROM_EMAIL}
SUPER_ADMIN_OTP_EMAIL=${SUPER_ADMIN_OTP_EMAIL}

# Media Storage
AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}
AWS_STORAGE_BUCKET_NAME=${AWS_STORAGE_BUCKET_NAME}
AWS_S3_REGION_NAME=us-east-1
AWS_S3_CUSTOM_DOMAIN=${CDN_DOMAIN}
USE_S3=True

# Security Settings
SECURE_PROXY_SSL_HEADER_HTTP_X_FORWARDED_PROTO=https
SECURE_SSL_REDIRECT=True
SESSION_COOKIE_SECURE=True
CSRF_COOKIE_SECURE=True
SECURE_BROWSER_XSS_FILTER=True
SECURE_CONTENT_TYPE_NOSNIFF=True
X_FRAME_OPTIONS=DENY
SECURE_HSTS_SECONDS=31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS=True

# Monitoring & Logging
SENTRY_DSN=${SENTRY_DSN}
LOG_LEVEL=INFO
ENABLE_MONITORING=True

# Performance
GUNICORN_WORKERS=4
GUNICORN_THREADS=2
GUNICORN_TIMEOUT=120
DATABASE_CONN_MAX_AGE=600

# Application Settings
SITE_URL=https://yourdomain.com
API_BASE_URL=https://api.yourdomain.com
FRONTEND_URL=https://app.yourdomain.com

# Feature Flags
ENABLE_DEBUG_TOOLBAR=False
ENABLE_SILK_PROFILER=False
ENABLE_RATE_LIMITING=True
ENABLE_CSRF_PROTECTION=True
```

---

## 🔧 Environment Variables Management

### Environment Variables Template

```bash
#!/bin/bash
# generate-env-template.sh

cat > .env.template << 'EOF'
# ==============================================
# PRS Backend Environment Configuration
# ==============================================

# Django Core Settings
SECRET_KEY=                          # 256-bit secret key for Django
DEBUG=                               # True for development, False for production
ALLOWED_HOSTS=                       # Comma-separated list of allowed hosts
DJANGO_SETTINGS_MODULE=              # Django settings module path

# Database Configuration
DATABASE_URL=                        # Full database URL
DB_NAME=                            # Database name
DB_USER=                            # Database username
DB_PASSWORD=                        # Database password
DB_HOST=                            # Database host
DB_PORT=                            # Database port (default: 5432)
DB_SSL_REQUIRE=                     # Require SSL for database connection

# Cache Configuration
REDIS_URL=                          # Redis connection URL
REDIS_PASSWORD=                     # Redis password (if required)
CELERY_BROKER_URL=                  # Celery broker URL
CELERY_RESULT_BACKEND=              # Celery result backend URL

# Email Configuration
EMAIL_HOST=                         # SMTP host
EMAIL_HOST_USER=                    # SMTP username
EMAIL_HOST_PASSWORD=                # SMTP password
EMAIL_PORT=                         # SMTP port
EMAIL_USE_TLS=                      # Use TLS for email
DEFAULT_FROM_EMAIL=                 # Default from email address
SUPER_ADMIN_OTP_EMAIL=             # Super admin OTP email

# Media Storage
AWS_ACCESS_KEY_ID=                  # AWS access key ID
AWS_SECRET_ACCESS_KEY=              # AWS secret access key
AWS_STORAGE_BUCKET_NAME=            # S3 bucket name for media files
AWS_S3_REGION_NAME=                 # AWS S3 region
AWS_S3_CUSTOM_DOMAIN=               # CloudFront domain (optional)
USE_S3=                            # Use S3 for media storage

# Security Settings
SECURE_PROXY_SSL_HEADER=            # SSL proxy header
SECURE_SSL_REDIRECT=                # Force SSL redirect
SESSION_COOKIE_SECURE=              # Secure session cookies
CSRF_COOKIE_SECURE=                 # Secure CSRF cookies

# Monitoring & Logging
SENTRY_DSN=                         # Sentry DSN for error tracking
LOG_LEVEL=                          # Logging level
ENABLE_MONITORING=                  # Enable monitoring

# Performance Settings
GUNICORN_WORKERS=                   # Number of Gunicorn workers
GUNICORN_THREADS=                   # Number of threads per worker
GUNICORN_TIMEOUT=                   # Request timeout
DATABASE_CONN_MAX_AGE=              # Database connection max age

# Application Settings
SITE_URL=                           # Main site URL
API_BASE_URL=                       # API base URL
FRONTEND_URL=                       # Frontend URL

# Feature Flags
ENABLE_DEBUG_TOOLBAR=               # Enable Django debug toolbar
ENABLE_SILK_PROFILER=              # Enable Silk profiler
ENABLE_RATE_LIMITING=              # Enable API rate limiting
ENABLE_CSRF_PROTECTION=            # Enable CSRF protection
EOF

echo "✅ Environment template created: .env.template"
echo "💡 Copy to .env.{environment} and fill in the values"
```

### Environment Validation Script

```python
#!/usr/bin/env python3
"""
validate-environment.py

Validates environment configuration for different environments.
"""

import os
import sys
from urllib.parse import urlparse

def validate_required_vars(env_vars, environment):
    """Validate that all required environment variables are set"""
    missing_vars = []
    
    for var in env_vars:
        value = os.getenv(var)
        if not value or value.strip() == '':
            missing_vars.append(var)
    
    if missing_vars:
        print(f"❌ Missing required environment variables for {environment}:")
        for var in missing_vars:
            print(f"   - {var}")
        return False
    
    return True

def validate_database_url():
    """Validate database URL format"""
    database_url = os.getenv('DATABASE_URL')
    if not database_url:
        return False
    
    try:
        parsed = urlparse(database_url)
        if not all([parsed.scheme, parsed.hostname, parsed.username, parsed.path]):
            print("❌ Invalid DATABASE_URL format")
            return False
        
        if parsed.scheme != 'postgresql':
            print("⚠️  Database scheme is not 'postgresql'")
        
        return True
    except Exception as e:
        print(f"❌ Error parsing DATABASE_URL: {e}")
        return False

def validate_redis_url():
    """Validate Redis URL format"""
    redis_url = os.getenv('REDIS_URL')
    if not redis_url:
        return False
    
    try:
        parsed = urlparse(redis_url)
        if not all([parsed.scheme, parsed.hostname]):
            print("❌ Invalid REDIS_URL format")
            return False
        
        if parsed.scheme != 'redis':
            print("⚠️  Redis scheme is not 'redis'")
        
        return True
    except Exception as e:
        print(f"❌ Error parsing REDIS_URL: {e}")
        return False

def validate_security_settings():
    """Validate security settings"""
    issues = []
    
    # Check secret key
    secret_key = os.getenv('SECRET_KEY')
    if not secret_key or len(secret_key) < 50:
        issues.append("SECRET_KEY should be at least 50 characters long")
    
    # Check debug setting
    debug = os.getenv('DEBUG', '').lower()
    if debug == 'true':
        issues.append("DEBUG should be False in production")
    
    # Check SSL settings
    ssl_redirect = os.getenv('SECURE_SSL_REDIRECT', '').lower()
    if ssl_redirect != 'true':
        issues.append("SECURE_SSL_REDIRECT should be True in production")
    
    if issues:
        print("⚠️  Security issues found:")
        for issue in issues:
            print(f"   - {issue}")
        return False
    
    return True

def validate_environment(environment):
    """Validate environment configuration"""
    print(f"🔍 Validating {environment} environment configuration...")
    
    # Define required variables per environment
    common_vars = [
        'SECRET_KEY', 'DJANGO_SETTINGS_MODULE', 'DATABASE_URL', 
        'REDIS_URL', 'DEFAULT_FROM_EMAIL'
    ]
    
    development_vars = common_vars + []
    staging_vars = common_vars + ['SENTRY_DSN', 'AWS_ACCESS_KEY_ID']
    production_vars = common_vars + [
        'SENTRY_DSN', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY',
        'EMAIL_HOST_PASSWORD', 'ALLOWED_HOSTS'
    ]
    
    # Select required vars based on environment
    if environment == 'development':
        required_vars = development_vars
    elif environment == 'staging':
        required_vars = staging_vars
    elif environment == 'production':
        required_vars = production_vars
    else:
        print(f"❌ Unknown environment: {environment}")
        return False
    
    # Validation steps
    validations = [
        validate_required_vars(required_vars, environment),
        validate_database_url(),
        validate_redis_url(),
    ]
    
    # Add security validation for production
    if environment in ['staging', 'production']:
        validations.append(validate_security_settings())
    
    # Check all validations
    all_valid = all(validations)
    
    if all_valid:
        print(f"✅ {environment} environment configuration is valid")
    else:
        print(f"❌ {environment} environment configuration has issues")
    
    return all_valid

def main():
    """Main validation function"""
    if len(sys.argv) != 2:
        print("Usage: python validate-environment.py <environment>")
        print("Environments: development, staging, production")
        sys.exit(1)
    
    environment = sys.argv[1].lower()
    
    # Load environment file
    env_file = f".env.{environment}"
    if os.path.exists(env_file):
        print(f"📄 Loading environment file: {env_file}")
        
        # Simple .env file loader
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ[key.strip()] = value.strip()
    else:
        print(f"⚠️  Environment file {env_file} not found, using system environment")
    
    # Validate environment
    is_valid = validate_environment(environment)
    
    if not is_valid:
        sys.exit(1)

if __name__ == '__main__':
    main()
```

---

This comprehensive environment setup guide provides detailed instructions for setting up the PRS backend across all environments, with proper infrastructure provisioning, security configurations, and validation procedures. Each environment is optimized for its specific purpose while maintaining consistency in deployment procedures.
