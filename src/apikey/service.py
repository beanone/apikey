"""Standalone service implementation for the API key management system.

This module provides a standalone FastAPI application that can be run as a service,
while still maintaining the library functionality for use in other applications.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from apikey import __version__
from apikey.db import init_db
from apikey.dependencies import get_settings
from apikey.router import api_key_router

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize and cleanup database connection."""
    # Startup: Initialize database
    await init_db()
    yield
    # Shutdown: Nothing to do here as we use SQLite


def create_app() -> FastAPI:
    """Create and configure the FastAPI application.

    Returns:
        FastAPI: Configured FastAPI application instance.
    """
    settings = get_settings()

    app = FastAPI(
        title="API Key Management Service",
        description="Standalone service for managing API keys",
        version=__version__,
        lifespan=lifespan,
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
