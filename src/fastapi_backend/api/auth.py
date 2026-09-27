"""
Authentication API endpoints: user login, session establishment, and logout.
"""
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr

from fastapi_backend.services.credential_service import CredentialValidator
from fastapi_backend.services.session_service import SessionManager

auth_router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class LoginResponse(BaseModel):
    status: str
    user_id: str
    session_id: str
    message: str


@auth_router.post("/login", response_model=LoginResponse)
async def login_endpoint(
    login_data: LoginRequest,
    response: Response,
    request: Request,
) -> LoginResponse:
    """
    API endpoint that handles user login.
    1. Validates user credentials using CredentialValidator.
    2. Issues a new authenticated session via SessionManager.
    3. Sets the session cookie on HTTP response for session preservation.
    """
    credential_validator: CredentialValidator = request.app.state.credential_validator
    session_manager: SessionManager = request.app.state.session_manager

    # Step 1: Credential validation
    user = credential_validator.validate_credentials(
        email=login_data.email,
        password=login_data.password,
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    # Step 2: Session creation
    client_ip = request.client.host if request.client else None
    session = session_manager.create_user_session(
        user_id=user.id,
        client_ip=client_ip,
    )

    # Step 3: Establish session cookie for state preservation
    response.set_cookie(
        key="session_id",
        value=session.session_id,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=86400,
    )

    return LoginResponse(
        status="success",
        user_id=user.id,
        session_id=session.session_id,
        message="Authentication successful",
    )


@auth_router.post("/logout")
async def logout_endpoint(request: Request, response: Response) -> dict[str, str]:
    """Logs out current user and revokes active session."""
    session_manager: SessionManager = request.app.state.session_manager
    session_id = request.cookies.get("session_id")
    if session_id:
        session_manager.revoke_session(session_id)
        response.delete_cookie("session_id")

    return {"status": "success", "message": "Logged out successfully"}
