# syntax=docker/dockerfile:1
FROM python:3.14-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install system deps (none needed for slim + pure-Python stack)
# Copy only dependency files first for better caching
COPY requirements.txt ./ 
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the app
COPY . .

# Default port (configurable via UNSEEN_PORT or config.yaml)
EXPOSE 8888

# Run as a module so package-relative imports work.
CMD ["python", "-m", "app.main"]
