"""
Authentication and session preservation middleware.
Extracts session identity from request headers or cookies and attaches verified
user state to request context for downstream API endpoints.
"""
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from fastapi_backend.services.session_service import SessionManager


class SessionPreservationMiddleware(BaseHTTPMiddleware):
    """
    Middleware responsible for preserving authenticated user state between HTTP requests.
    Inspects incoming requests for session cookies or Authorization headers, validates
    session continuity against SessionManager, and attaches authenticated identity to request.state.
    """

    def __init__(self, app, session_manager: SessionManager) -> None:
        super().__init__(app)
        self.session_manager = session_manager

    async def dispatch(self, request: Request, call_next) -> Response:
        # Default unauthenticated state
        request.state.user_id = None
        request.state.session = None
        request.state.is_authenticated = False

        # 1. Attempt session extraction from cookie
        session_id = request.cookies.get("session_id")

        # 2. Fallback to Authorization Bearer header
        if not session_id:
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
                session_id = auth_header[7:].strip()

        # 3. Validate session continuity and preserve authenticated identity
        if session_id:
            active_session = self.session_manager.get_session(session_id)
            if active_session:
                request.state.user_id = active_session.user_id
                request.state.session = active_session
                request.state.is_authenticated = True

        response = await call_next(request)
        return response
