"""
Application entry point for FastAPI backend.
Wires together credential validation, session management, auth middleware, and API endpoints.
"""
from fastapi import FastAPI

from fastapi_backend.api.auth import auth_router
from fastapi_backend.api.users import users_router
from fastapi_backend.middleware.auth_middleware import SessionPreservationMiddleware
from fastapi_backend.models.user import User
from fastapi_backend.services.credential_service import CredentialValidator
from fastapi_backend.services.session_service import SessionManager


def create_application() -> FastAPI:
    """Builds and configures the FastAPI application instance."""
    app = FastAPI(
        title="Backend Authentication API",
        version="0.1.0",
        description="FastAPI service with modular authentication, session preservation, and user APIs",
    )

    # Initialize core services
    credential_validator = CredentialValidator()
    session_manager = SessionManager(session_ttl_hours=24)

    # Attach to application state
    app.state.credential_validator = credential_validator
    app.state.session_manager = session_manager

    # Register session preservation middleware (runs on all requests)
    app.add_middleware(
        SessionPreservationMiddleware,
        session_manager=session_manager,
    )

    # Register routers
    app.include_router(auth_router)
    app.include_router(users_router)

    return app


app = create_application()
