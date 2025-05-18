# BeanOne API Key Router

[![Python Versions](https://img.shields.io/pypi/pyversions/beanone-apikey)](https://pypi.org/project/beanone-apikey)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Tests](https://github.com/yourusername/apikey/actions/workflows/tests.yml/badge.svg)](https://github.com/yourusername/apikey/actions?query=workflow%3Atests)
[![Coverage](https://codecov.io/gh/yourusername/apikey/branch/main/graph/badge.svg)](https://codecov.io/gh/yourusername/apikey)
[![Code Quality](https://img.shields.io/badge/code%20style-ruff-000000)](https://github.com/astral-sh/ruff)
[![PyPI version](https://img.shields.io/pypi/v/beanone-apikey)](https://pypi.org/project/beanone-apikey)

A reusable FastAPI router for API key management, built on top of the userdb library.

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
- API key revocation
- API key listing
- Built on userdb for core functionality

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api-keys/` | POST | Create a new API key |
| `/api-keys/` | GET | List all API keys |
| `/api-keys/{key_id}` | DELETE | Delete (revoke) an API key |

## Login Service Integration

This API key service is designed to work with the BeanOne login service. Here's how they integrate:

### Authentication Flow

1. Users first authenticate through the login service
2. After successful login, users can generate API keys
3. API keys are associated with the authenticated user's account
4. API keys can be used for programmatic access to protected endpoints

### Dependencies

The API key service requires:
- A running instance of the BeanOne login service
- Valid JWT tokens from the login service for authentication
- User information from the login service for API key association

### Configuration

To configure the integration with the login service:

```python
from fastapi import FastAPI
from apikey import api_key_router, LoginServiceConfig

app = FastAPI()

# Configure login service integration
login_config = LoginServiceConfig(
    login_service_url="https://login.beanone.com",  # Your login service URL
    jwt_secret="your-jwt-secret",                   # Shared JWT secret
    user_info_endpoint="/api/v1/user"              # Endpoint to fetch user info
)

# Include the router with login service configuration
app.include_router(api_key_router, login_config=login_config)
```

### Security

- All API key endpoints require valid JWT tokens from the login service
- API keys are scoped to the user's permissions from the login service
- API key operations are logged and audited
- Revoked API keys are immediately invalidated

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

## License

MIT
