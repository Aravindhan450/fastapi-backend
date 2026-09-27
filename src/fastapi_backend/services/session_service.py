"""Session creation, persistence, and invalidation service."""
import secrets
from datetime import datetime, timedelta, timezone
from fastapi_backend.models.session import UserSession


class SessionManager:
    """Manages active user sessions, token issuance, and session expiration."""

    def __init__(self, session_ttl_hours: int = 24) -> None:
        self.session_ttl = timedelta(hours=session_ttl_hours)
        self._sessions: dict[str, UserSession] = {}

    def create_user_session(self, user_id: str, client_ip: str | None = None) -> UserSession:
        """
        Issues a new cryptographically secure session token and persists user session.
        """
        token = secrets.token_urlsafe(32)
        now = datetime.now(timezone.utc)
        session = UserSession(
            session_id=token,
            user_id=user_id,
            created_at=now,
            expires_at=now + self.session_ttl,
            is_revoked=False,
            client_ip=client_ip,
        )
        self._sessions[token] = session
        return session

    def get_session(self, session_id: str) -> UserSession | None:
        """Retrieves an active, non-expired, non-revoked session."""
        session = self._sessions.get(session_id)
        if not session or session.is_revoked:
            return None

        now = datetime.now(timezone.utc)
        if session.expires_at < now:
            session.is_revoked = True
            return None

        return session

    def revoke_session(self, session_id: str) -> bool:
        """Explicitly revokes an active session."""
        session = self._sessions.get(session_id)
        if session:
            session.is_revoked = True
            return True
        return False
