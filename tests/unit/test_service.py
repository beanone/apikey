"""Unit tests for the API key service module."""

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from apikey import __version__
from apikey.service import create_app


@pytest.fixture
def mock_settings():
    """Mock settings for testing."""
    with patch("apikey.dependencies.get_settings") as mock:
        mock.return_value.cors_origins = ["*"]
        mock.return_value.login_url = "http://localhost:8001"
        mock.return_value.jwt_secret = "test-secret"
        mock.return_value.jwt_algorithm = "HS256"
        yield mock


@pytest.fixture
def client(mock_settings) -> TestClient:
    """Create a test client for the FastAPI application.

    Args:
        mock_settings: The mock settings fixture.

    Returns:
        TestClient: A test client instance.
    """
    app = create_app()
    return TestClient(app)


def test_health_check(client: TestClient) -> None:
    """Test the health check endpoint.

    Args:
        client: The test client fixture.
    """
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_api_documentation(client: TestClient) -> None:
    """Test that the API documentation is available.

    Args:
        client: The test client fixture.
    """
    response = client.get("/docs")
    assert response.status_code == 200
    assert "API Key Management Service" in response.text


def test_openapi_schema(client: TestClient) -> None:
    """Test that the OpenAPI schema is available.

    Args:
        client: The test client fixture.
    """
    response = client.get("/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    assert schema["info"]["title"] == "API Key Management Service"
    assert schema["info"]["version"] == __version__
