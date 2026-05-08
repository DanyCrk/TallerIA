import structlog
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from fastapi import HTTPException, status

from app.models.user import User
from app.schemas.auth import RegisterRequest, LoginRequest, UserResponse
from app.core.security import (
    hash_password, verify_password, create_access_token, create_refresh_token,
    verify_token, verify_token_side_by_side, generate_reset_token, hash_reset_token
)
from app.core.config import settings

logger = structlog.get_logger()

class AuthService:
    
    @staticmethod
    def register(db: Session, user_data: RegisterRequest) -> UserResponse:
        # Normalize email
        normalized_email = user_data.email.lower().strip()
        
        # Check if user exists (race condition handled by DB unique constraint)
        existing_user = db.query(User).filter(User.email == normalized_email).first()
        if existing_user:
            logger.warning("registration_failed_email_exists", email=normalized_email)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )
        
        # Create new user
        hashed_pw = hash_password(user_data.password)
        db_user = User(
            email=normalized_email,
            hashed_password=hashed_pw,
            full_name=user_data.full_name.strip()
        )
        
        try:
            db.add(db_user)
            db.commit()
            db.refresh(db_user)
            logger.info("user_registered", user_id=str(db_user.id), email=normalized_email)
            return UserResponse.model_validate(db_user)
        except IntegrityError:
            db.rollback()
            logger.error("registration_race_condition", email=normalized_email)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already registered"
            )
    
    @staticmethod
    def login(db: Session, login_data: LoginRequest, client_ip: str, user_agent: str) -> dict:
        normalized_email = login_data.email.lower().strip()
        user = db.query(User).filter(User.email == normalized_email).first()
        
        # Neutral response for non-existent user
        if not user:
            logger.info("login_failed_user_not_found", email=normalized_email, ip=client_ip)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        # Check if account is locked
        if user.locked_until and user.locked_until > datetime.now(timezone.utc):
            remaining = user.locked_until - datetime.now(timezone.utc)
            logger.warning("login_blocked_account_locked", user_id=str(user.id), remaining_seconds=remaining.total_seconds())
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Account locked. Try again in {remaining.seconds // 60} minutes"
            )
        
        # Verify password
        if not verify_password(login_data.password, user.hashed_password):
            user.failed_attempts += 1
            if user.failed_attempts >= 5:
                user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)
                logger.warning("account_locked_due_to_brute_force", user_id=str(user.id))
            db.commit()
            logger.info("login_failed_invalid_password", user_id=str(user.id), attempts=user.failed_attempts)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        # Reset failed attempts on successful login
        user.failed_attempts = 0
        user.locked_until = None
        
        # Generate tokens
        access_token = create_access_token(str(user.id))
        refresh_token, refresh_token_hash = create_refresh_token(str(user.id))
        user.refresh_token_hash = refresh_token_hash
        
        db.commit()
        
        logger.info("user_logged_in", user_id=str(user.id), ip=client_ip, user_agent=user_agent)
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer"
        }
    
    @staticmethod
    def refresh_tokens(db: Session, refresh_token: str, client_ip: str) -> dict:
        # Verify token signature and expiration
        user_id = verify_token(refresh_token, token_type="refresh")
        if not user_id:
            logger.warning("refresh_failed_invalid_token", ip=client_ip)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired refresh token"
            )
        
        user = db.query(User).filter(User.id == user_id).first()
        if not user or not user.refresh_token_hash:
            logger.warning("refresh_failed_user_not_found_or_no_token", user_id=user_id)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
        
        # Timing-safe verification
        if not verify_token_side_by_side(refresh_token, user.refresh_token_hash):
            # Token reuse detected - potential attack
            logger.critical("refresh_token_reuse_detected", user_id=str(user.id), ip=client_ip)
            # Invalidate all tokens and lock account
            user.refresh_token_hash = None
            user.is_active = False
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token reuse detected. Account suspended."
            )
        
        # Rotate tokens (invalidate old, create new)
        new_access_token = create_access_token(str(user.id))
        new_refresh_token, new_refresh_token_hash = create_refresh_token(str(user.id))
        user.refresh_token_hash = new_refresh_token_hash
        db.commit()
        
        logger.info("tokens_refreshed", user_id=str(user.id), ip=client_ip)
        
        return {
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
            "token_type": "bearer"
        }
    
    @staticmethod
    def request_password_reset(db: Session, email: str):
        normalized_email = email.lower().strip()
        user = db.query(User).filter(User.email == normalized_email).first()
        
        # Always return 200 OK (neutral response)
        if not user:
            logger.info("password_reset_requested_for_nonexistent_email", email=normalized_email)
            return
        
        # Generate token and store hash
        token = generate_reset_token()
        token_hash = hash_reset_token(token)
        user.reset_token_hash = token_hash
        user.reset_token_expires = datetime.now(timezone.utc) + timedelta(minutes=settings.RESET_TOKEN_EXPIRE_MINUTES)
        db.commit()
        
        # TODO: Send email asynchronously (use background tasks or message queue)
        logger.info("password_reset_token_generated", user_id=str(user.id), email=normalized_email)
        
        # In production, send email via SMTP here
        # await send_reset_email(user.email, token)
    
    @staticmethod
    def confirm_password_reset(db: Session, token: str, new_password: str) -> None:
        token_hash = hash_reset_token(token)
        user = db.query(User).filter(
            User.reset_token_hash == token_hash,
            User.reset_token_expires > datetime.now(timezone.utc)
        ).first()
        
        if not user:
            logger.warning("password_reset_failed_invalid_token")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired reset token"
            )
        
        # Update password and clear reset token
        user.hashed_password = hash_password(new_password)
        user.reset_token_hash = None
        user.reset_token_expires = None
        user.failed_attempts = 0
        user.locked_until = None
        db.commit()
        
        logger.info("password_reset_successful", user_id=str(user.id))
    
    @staticmethod
    def get_profile(db: Session, user_id: str) -> UserResponse:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        return UserResponse.model_validate(user)