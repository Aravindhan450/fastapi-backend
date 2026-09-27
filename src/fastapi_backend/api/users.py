"""
User profile and account API routes requiring authenticated session.
"""
from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel

users_router = APIRouter(prefix="/api/v1/users", tags=["users"])


class UserProfileResponse(BaseModel):
    user_id: str
    is_authenticated: bool
    status: str


@users_router.get("/me", response_model=UserProfileResponse)
async def get_current_user_profile(request: Request) -> UserProfileResponse:
    """
    Protected API endpoint.
    Relies on SessionPreservationMiddleware having preserved authenticated identity on request.state.
    """
    if not getattr(request.state, "is_authenticated", False) or not request.state.user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required: no active session found for request",
        )

    return UserProfileResponse(
        user_id=request.state.user_id,
        is_authenticated=True,
        status="active",
    )
