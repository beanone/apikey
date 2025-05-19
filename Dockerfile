FROM python:3.11-slim

LABEL maintainer="Branone Team <branone@example.com>"
LABEL description="API Key Management Service"
LABEL version="1.0.0"

WORKDIR /app

# Copy only requirements first to leverage cache
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire repository for package installation
COPY . .

# Install the package in development mode
RUN pip install -e .

# Add non-root user and set permissions
RUN adduser --disabled-password --gecos "" appuser && \
    chown -R appuser:appuser /app && \
    chmod -R 755 /app

USER appuser

# Add health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8002/health || exit 1

CMD ["uvicorn", "src.apikey.service:app", "--host", "0.0.0.0", "--port", "8002"]
