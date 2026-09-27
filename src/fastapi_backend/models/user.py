"""User data models."""
from pydantic import BaseModel, EmailStr


class User(BaseModel):
    """User account entity representing a registered system user."""
    id: str
    email: EmailStr
    hashed_password: str
    is_active: bool = True
    full_name: str | None = None
