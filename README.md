# API Key Management Library

[![Python Versions](https://img.shields.io/pypi/pyversions/beanone-apikey)](https://pypi.org/project/beanone-apikey)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Tests](https://github.com/yourusername/apikey/actions/workflows/tests.yml/badge.svg)](https://github.com/yourusername/apikey/actions?query=workflow%3Atests)
[![Coverage](https://codecov.io/gh/yourusername/apikey/branch/main/graph/badge.svg)](https://codecov.io/gh/yourusername/apikey)
[![Code Quality](https://img.shields.io/badge/code%20style-ruff-000000)](https://github.com/astral-sh/ruff)
[![PyPI version](https://img.shields.io/pypi/v/beanone-apikey)](https://pypi.org/project/beanone-apikey)

A library for API key management and JWT validation, designed to be integrated into services that need to handle API key operations and authentication.

## Overview

This library provides:
- API key model and persistence
- API key generation and validation
- JWT validation
- Key management endpoints
- Database access layer

## Installation

```bash
pip install beanone-apikey
```

## Quick Start

```python
from fastapi import FastAPI
from apikey import api_key_router

app = FastAPI()
app.include_router(api_key_router)
```

## Features

- API key generation and management
- API key validation
- JWT validation
- API key listing and deletion
- Secure key storage with hashing
- Async database operations
- FastAPI integration

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api-keys/` | POST | Create a new API key |
| `/api-keys/` | GET | List all API keys |
| `/api-keys/{key_id}` | DELETE | Delete an API key |

## Authentication

The library supports two authentication methods:

1. **JWT Authentication**
   - Validates JWTs issued by the login service
   - Extracts user information from JWT claims
   - Supports audience validation

2. **API Key Authentication**
   - Validates API keys in requests
   - Supports both header and query parameter authentication
   - Checks key status and expiration

## Configuration

Environment variables:
- `DATABASE_URL`: Database connection URL (default: sqlite+aiosqlite:///./apikey.db)
- `JWT_SECRET`: Secret for JWT validation
- `JWT_ALGORITHM`: JWT algorithm (default: HS256)
- `LOGIN_URL`: Login service URL (default: http://localhost:8001)

### Database Configuration
- For development: SQLite (default)
- For production: PostgreSQL
  - `POSTGRES_USER`: Database user (default: postgres)
  - `POSTGRES_PASSWORD`: Database password (default: password)
  - `POSTGRES_DB`: Database name (default: apikeydb)

## Development

1. Clone the repository
2. Install development dependencies:
   ```bash
   pip install -e ".[dev]"
   ```
3. Run tests:
   ```bash
   pytest
   ```

## Starting a New Development Instance

1. **Set up the environment**
   ```bash
   # Create and activate virtual environment
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate

   # Install dependencies
   pip install -r requirements.txt
   pip install -r requirements-test.txt
   ```

2. **Configure environment variables**
   Create a `.env` file in the project root:
   ```bash
   # Database configuration
   DATABASE_URL=sqlite+aiosqlite:///./apikey.db  # For local development
   # DATABASE_URL=postgresql+asyncpg://postgres:password@localhost:5432/apikeydb  # For PostgreSQL

   # JWT configuration
   JWT_SECRET=your-secret-key
   JWT_ALGORITHM=HS256
   LOGIN_URL=http://localhost:8001

   # Optional: PostgreSQL configuration
   POSTGRES_USER=postgres
   POSTGRES_PASSWORD=password
   POSTGRES_DB=apikeydb
   ```

3. **Start the development server**
   ```bash
   # Using uvicorn directly
   uvicorn src.apikey.service:app --reload --port 8002

   # Or using Docker Compose for development
   docker-compose -f docker-compose.dev.yml up -d
   ```

4. **Verify the setup**
   - Check the health endpoint: `http://localhost:8002/health`
   - Access the API documentation: `http://localhost:8002/docs`
   - Run the test suite: `pytest`

5. **Development workflow**
   - The server will automatically reload on code changes
   - Use the API documentation to test endpoints
   - Check logs: `docker-compose -f docker-compose.dev.yml logs -f apikey`

## Docker Deployment

### Production Deployment

1. Create a `.env` file with required environment variables
2. Run with Docker Compose:
   ```bash
   docker-compose up -d
   ```

The service will be available at `http://localhost:8002`

### Development Deployment

1. Create a `.env` file with required environment variables
2. Run with development Docker Compose:
   ```bash
   docker-compose -f docker-compose.dev.yml up -d
   ```

Development features:
- Hot reload enabled
- Source code mounted for live updates
- PostgreSQL database with persistent volume
- Health checks configured

### Docker Configuration

- Service runs on port 8002
- Health check endpoint: `/health`
- Resource limits:
  - CPU: 0.5 cores
  - Memory: 512MB
- Logging: JSON format with rotation (10MB max, 3 files)

## Architecture

This library is designed to be integrated into services that need to:
- Manage API keys for their users
- Validate incoming requests using either JWTs or API keys
- Store and manage API key data

The library follows a distributed API key management pattern where:
- Each service maintains its own API key database
- API key validation is performed locally
- JWT validation is performed against the login service

## Security

- API keys are hashed before storage
- JWT validation includes audience checks
- API key validation checks status and expiration
- All endpoints require authentication
- Database operations use parameterized queries
- Non-root user in Docker container
- Resource limits enforced
- Health checks implemented

## License

MIT
