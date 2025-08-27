# Use Python 3.11 slim
FROM python:3.11-slim

# Environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install system dependencies for libmagic, PostgreSQL, and build tools
RUN apt-get update && apt-get install -y \
    libmagic1 \
    file \
    gcc \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for caching
COPY requirements.txt .

# Upgrade pip and install Python dependencies
RUN pip install --upgrade pip setuptools wheel
RUN pip install --no-cache-dir -r requirements.txt

# Copy the project
COPY . .

# Create necessary directories
RUN mkdir -p /app/staticfiles /app/media /app/logs

# Expose port
EXPOSE 8000

# Start ASGI server with Daphne
CMD ["daphne", "-b", "0.0.0.0", "-p", "8000", "core_config.asgi:application"]
