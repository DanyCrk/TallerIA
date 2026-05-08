"""
auth.py – FastAPI router exposing all authentication endpoints.
Rate limiting is applied per-IP via SlowAPI middleware (configured in main.py).
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.auth import (
    LoginRequest,
    MessageResponse,
    PasswordResetConfirm,
    PasswordResetRequestBody,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
    UserProfile,
)
from app.services import auth_service

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


def _bearer_token(request: Request) -> str:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header.",
        )
    return auth[len("Bearer "):]


# ── POST /register ────────────────────────────────────────────────────────────

@router.post("/register", status_code=status.HTTP_201_CREATED, response_model=UserProfile)
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    try:
        user = auth_service.register_user(db, payload)
    except ValueError as exc:
        if "email_taken" in str(exc):
            raise HTTPException(status_code=400, detail="Email already registered.")
        raise HTTPException(status_code=422, detail=str(exc))
    return user


# ── POST /login ───────────────────────────────────────────────────────────────

@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    try:
        tokens = auth_service.login_user(db, payload)
    except PermissionError as exc:
        msg = str(exc)
        if msg.startswith("account_locked:"):
            secs = msg.split(":")[1]
            raise HTTPException(
                status_code=403,
                detail=f"Account locked. Try again in {secs} seconds.",
            )
        raise HTTPException(status_code=401, detail="Invalid credentials.")
    return {**tokens, "token_type": "bearer"}


# ── POST /refresh ─────────────────────────────────────────────────────────────

@router.post("/refresh", response_model=TokenResponse)
def refresh(payload: RefreshRequest, db: Session = Depends(get_db)):
    try:
        tokens = auth_service.refresh_tokens(db, payload.refresh_token)
    except PermissionError:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token.")
    return {**tokens, "token_type": "bearer"}


# ── POST /password-reset/request ──────────────────────────────────────────────

@router.post("/password-reset/request", response_model=MessageResponse)
async def password_reset_request(
    payload: PasswordResetRequestBody, db: Session = Depends(get_db)
):
    # Always 200 OK – never reveal if email exists (RF-07)
    auth_service.request_password_reset(db, payload.email)
    return {"message": "If that email is registered, a reset link has been sent."}


# ── POST /password-reset/confirm ──────────────────────────────────────────────

@router.post("/password-reset/confirm", response_model=MessageResponse)
def password_reset_confirm(payload: PasswordResetConfirm, db: Session = Depends(get_db)):
    try:
        auth_service.confirm_password_reset(db, payload)
    except ValueError as exc:
        msg = str(exc)
        if "expired" in msg:
            raise HTTPException(status_code=400, detail="Reset token has expired.")
        raise HTTPException(status_code=400, detail="Invalid reset token.")
    return {"message": "Password updated successfully."}


# ── GET /me ───────────────────────────────────────────────────────────────────

@router.get("/me", response_model=UserProfile)
def me(request: Request, db: Session = Depends(get_db)):
    token = _bearer_token(request)
    try:
        user = auth_service.get_current_user(db, token)
    except PermissionError:
        raise HTTPException(status_code=401, detail="Invalid or expired token.")
    return user
