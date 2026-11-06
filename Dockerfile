# Production-Grade Dockerfile for GhostShare Web Vault
FROM python:3.11-slim

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# Install minimal OS dependencies for Pillow and OpenCV headless
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libgl1 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency definition
COPY requirements.txt .

# Install Python packages
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY core/ ./core/
COPY data/ ./data/
COPY input/ ./input/
COPY scripts/ ./scripts/
COPY app.py .
COPY ghostshare_cli.py .

# Create non-root user for security hardening
RUN useradd -m -u 1000 ghostuser && \
    mkdir -p /app/output && \
    chown -R ghostuser:ghostuser /app

USER ghostuser

# Expose Streamlit default port
EXPOSE 8501

# Health check to ensure the container is responsive
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl --fail http://localhost:8501/_stcore/health || exit 1

# Launch GhostShare Web Vault
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0", "--server.headless=true", "--server.enableCORS=false", "--server.enableXsrfProtection=true"]
