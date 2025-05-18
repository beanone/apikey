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
- `LOCKSMITHA_URL`: Login service URL (default: http://localhost:8001)

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

## License

MIT
