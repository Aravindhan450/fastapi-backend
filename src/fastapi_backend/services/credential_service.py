"""Credential validation and verification service."""
import hashlib
from fastapi_backend.models.user import User


class CredentialValidator:
    """Validates user login credentials against secure password hashes."""

    def __init__(self, user_database: dict[str, User] | None = None) -> None:
        self._users = user_database or {}

    def hash_password(self, password: str, salt: str = "app_salt") -> str:
        """Derives cryptographic hash for password storage and comparison."""
        return hashlib.sha256(f"{salt}:{password}".encode("utf-8")).hexdigest()

    def validate_credentials(self, email: str, password: str) -> User | None:
        """
        Validates user credentials.
        Returns the User instance if email exists and password hash matches, else None.
        """
        user = self._users.get(email.lower().strip())
        if not user or not user.is_active:
            return None

        expected_hash = self.hash_password(password)
        if user.hashed_password == expected_hash:
            return user
        return None
