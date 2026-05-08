from fastapi import APIRouter, Depends, Request, HTTPException, status
from sqlalchemy.orm import Session
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.db.session import get_db
from app.services.auth_service import AuthService
from app.schemas.auth import (
    RegisterRequest, LoginRequest, TokenResponse, RefreshRequest,
    PasswordResetRequest, PasswordResetConfirm, UserResponse
)
from app.core.dependencies import get_current_user
from app.core.config import settings

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(user_data: RegisterRequest, db: Session = Depends(get_db)):
    """Register a new user"""
    return AuthService.register(db, user_data)

@router.post("/login", response_model=TokenResponse)
@limiter.limit(f"{settings.RATE_LIMIT_PER_MINUTE}/minute")
async def login(
    request: Request,
    login_data: LoginRequest,
    db: Session = Depends(get_db)
):
    """Authenticate user and return JWT tokens"""
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "unknown")
    return AuthService.login(db, login_data, client_ip, user_agent)

@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(refresh_data: RefreshRequest, request: Request, db: Session = Depends(get_db)):
    """Refresh access token using refresh token (with rotation)"""
    client_ip = request.client.host
    return AuthService.refresh_tokens(db, refresh_data.refresh_token, client_ip)

@router.post("/password-reset/request")
@limiter.limit(f"{settings.RATE_LIMIT_PER_MINUTE}/minute")
async def request_password_reset(
    request: Request,
    reset_data: PasswordResetRequest,
    db: Session = Depends(get_db)
):
    """Request a password reset email (always returns 200)"""
    AuthService.request_password_reset(db, reset_data.email)
    return {"message": "If your email is registered, you will receive a reset link"}

@router.post("/password-reset/confirm")
async def confirm_password_reset(confirm_data: PasswordResetConfirm, db: Session = Depends(get_db)):
    """Reset password using a valid reset token"""
    AuthService.confirm_password_reset(db, confirm_data.token, confirm_data.new_password)
    return {"message": "Password reset successful"}

@router.get("/me", response_model=UserResponse)
async def get_profile(current_user: UserResponse = Depends(get_current_user)):
    """Get current user profile"""
    return current_user