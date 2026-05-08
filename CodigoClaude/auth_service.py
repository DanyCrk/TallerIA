"""
auth_service.py – Business logic layer for authentication operations.
All email lookups normalise to lower-case before hitting the DB to satisfy RF-10.
"""

import asyncio
import logging
import smtplib
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    generate_reset_token,
    hash_password,
    hash_reset_token,
    secure_compare,
    verify_password,
)
from app.models.user import User
from app.schemas.auth import (
    LoginRequest,
    PasswordResetConfirm,
    RegisterRequest,
)

logger = logging.getLogger(__name__)

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _get_user_by_email(db: Session, email: str) -> User | None:
    return db.query(User).filter(User.email == email.lower()).first()


def _is_locked(user: User) -> bool:
    if user.locked_until is None:
        return False
    lu = user.locked_until
    # SQLite stores datetimes as naive; make timezone-aware if needed
    if lu.tzinfo is None:
        lu = lu.replace(tzinfo=timezone.utc)
    return lu > _now()


def _lock_remaining_seconds(user: User) -> int:
    if user.locked_until is None:
        return 0
    lu = user.locked_until
    if lu.tzinfo is None:
        lu = lu.replace(tzinfo=timezone.utc)
    delta = (lu - _now()).total_seconds()
    return max(0, int(delta))


# ── Register ──────────────────────────────────────────────────────────────────

def register_user(db: Session, payload: RegisterRequest) -> User:
    email = payload.email.lower()
    existing = _get_user_by_email(db, email)
    if existing:
        raise ValueError("email_taken")

    user = User(
        email=email,
        full_name=payload.full_name,
        hashed_password=hash_password(payload.password),
    )
    db.add(user)
    try:
        db.commit()
        db.refresh(user)
    except IntegrityError:
        db.rollback()
        raise ValueError("email_taken")
    return user


# ── Login ─────────────────────────────────────────────────────────────────────

def login_user(db: Session, payload: LoginRequest) -> dict:
    email = payload.email.lower()
    user = _get_user_by_email(db, email)

    if user is None:
        raise PermissionError("invalid_credentials")

    if _is_locked(user):
        raise PermissionError(f"account_locked:{_lock_remaining_seconds(user)}")

    if not verify_password(payload.password, user.hashed_password):
        user.failed_attempts += 1
        if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
            user.locked_until = _now() + timedelta(minutes=LOCKOUT_MINUTES)
            logger.warning("Account locked after failed attempts: %s", email)
        db.commit()
        raise PermissionError("invalid_credentials")

    # Successful login – reset counters
    user.failed_attempts = 0
    user.locked_until = None

    access_token = create_access_token(user.id)
    refresh_token = create_refresh_token(user.id)
    user.refresh_token_hash = hash_reset_token(refresh_token)  # reuse SHA-256 helper

    db.commit()
    return {"access_token": access_token, "refresh_token": refresh_token}


# ── Refresh ───────────────────────────────────────────────────────────────────

def refresh_tokens(db: Session, refresh_token: str) -> dict:
    try:
        payload = decode_token(refresh_token)
    except Exception:
        raise PermissionError("invalid_token")

    if payload.get("type") != "refresh":
        raise PermissionError("invalid_token")

    user_id: str = payload.get("sub", "")
    user = db.query(User).filter(User.id == user_id).first()

    if user is None or user.refresh_token_hash is None:
        raise PermissionError("invalid_token")

    incoming_hash = hash_reset_token(refresh_token)
    stored_hash = user.refresh_token_hash or ""
    if not secure_compare(incoming_hash, stored_hash):
        raise PermissionError("invalid_token")

    # Rotate: invalidate old, issue new pair
    new_access = create_access_token(user.id)
    new_refresh = create_refresh_token(user.id)
    user.refresh_token_hash = hash_reset_token(new_refresh)
    db.commit()

    return {"access_token": new_access, "refresh_token": new_refresh}


# ── Password reset request ────────────────────────────────────────────────────

def request_password_reset(db: Session, email: str) -> None:
    """Always returns immediately; real work is done asynchronously."""
    user = _get_user_by_email(db, email.lower())
    if user is None:
        return  # Silent – do not reveal email existence (RF-07)

    token = generate_reset_token()
    user.reset_token = hash_reset_token(token)
    user.reset_token_exp = _now() + timedelta(minutes=settings.RESET_TOKEN_EXPIRE_MINUTES)
    db.commit()

    # Fire and forget – send email outside request/response cycle
    asyncio.create_task(_send_reset_email(user.email, token))


async def _send_reset_email(to: str, token: str) -> None:
    try:
        msg = MIMEText(
            f"Your password reset token is:\n\n{token}\n\n"
            f"It expires in {settings.RESET_TOKEN_EXPIRE_MINUTES} minutes."
        )
        msg["Subject"] = "Password Reset Request"
        msg["From"] = settings.SMTP_FROM
        msg["To"] = to

        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as smtp:
            smtp.starttls()
            if settings.SMTP_USER:
                smtp.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            smtp.sendmail(settings.SMTP_FROM, [to], msg.as_string())
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to send reset email to %s: %s", to, exc)


# ── Password reset confirm ────────────────────────────────────────────────────

def confirm_password_reset(db: Session, payload: PasswordResetConfirm) -> None:
    token_hash = hash_reset_token(payload.token)

    # Find user by hashed token using constant-time approach
    users = db.query(User).filter(User.reset_token.isnot(None)).all()
    matched: User | None = None
    for u in users:
        if u.reset_token and secure_compare(token_hash, u.reset_token):
            matched = u
            break

    if matched is None:
        raise ValueError("invalid_token")

    exp = matched.reset_token_exp
    if exp is None:
        raise ValueError("token_expired")
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    if exp < _now():
        raise ValueError("token_expired")

    matched.hashed_password = hash_password(payload.new_password)
    matched.reset_token = None
    matched.reset_token_exp = None
    db.commit()


# ── Get current user ──────────────────────────────────────────────────────────

def get_current_user(db: Session, token: str) -> User:
    try:
        payload = decode_token(token)
    except Exception:
        raise PermissionError("invalid_token")

    if payload.get("type") != "access":
        raise PermissionError("invalid_token")

    user_id: str = payload.get("sub", "")
    user = db.query(User).filter(User.id == user_id).first()

    if user is None or not user.is_active:
        raise PermissionError("invalid_token")

    return user
