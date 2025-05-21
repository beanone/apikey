FROM python:3.11-slim

# Get version from build arg
ARG VERSION=0.0.0

LABEL maintainer="Branone Team <branone@example.com>"
LABEL description="API Key Management Service"
LABEL version="${VERSION}"

WORKDIR /app

# Copy only requirements first to leverage cache
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy only the src directory
COPY src/ ./src/

# Set environment variables
ENV PYTHONPATH=/app/src
ENV LOGIN_URL=http://localhost:8001
ENV JWT_SECRET=supersecretjwtkey
ENV JWT_ALGORITHM=HS256

# Add non-root user and set permissions
RUN adduser --disabled-password --gecos "" appuser && \
    chown -R appuser:appuser /app && \
    chmod -R 755 /app

USER appuser

# Add health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8002/health || exit 1

CMD ["uvicorn", "src.apikey.service:app", "--host", "0.0.0.0", "--port", "8002"]
