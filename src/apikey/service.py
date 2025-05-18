"""Standalone service implementation for the API key management system.

This module provides a standalone FastAPI application that can be run as a service,
while still maintaining the library functionality for use in other applications.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from apikey.dependencies import get_settings
from apikey.router import api_key_router


def create_app() -> FastAPI:
    """Create and configure the FastAPI application.

    Returns:
        FastAPI: Configured FastAPI application instance.
    """
    settings = get_settings()

    app = FastAPI(
        title="API Key Management Service",
        description="Standalone service for managing API keys",
        version="0.1.0",
    )

    # Configure CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Include the API key router
    app.include_router(api_key_router, prefix="/api/v1", tags=["api-keys"])

    @app.get("/health")
    async def health_check():
        """Health check endpoint for Docker and monitoring."""
        return {"status": "healthy"}

    return app


app = create_app()
