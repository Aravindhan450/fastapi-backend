"""Session data models."""
from datetime import datetime
from pydantic import BaseModel


class UserSession(BaseModel):
    """User session model for tracking authenticated state."""
    session_id: str
    user_id: str
    created_at: datetime
    expires_at: datetime
    is_revoked: bool = False
    client_ip: str | None = None
