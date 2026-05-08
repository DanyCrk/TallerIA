import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from jose import jwt, JWTError
from passlib.context import CryptContext
from app.core.config import settings

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=settings.BCRYPT_ROUNDS)

def hash_password(password: str) -> str:
    """Hash a password using bcrypt"""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against a bcrypt hash"""
    return pwd_context.verify(plain_password, hashed_password)

# JWT functions
def create_access_token(subject: str) -> str:
    """Create a short-lived JWT access token"""
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {"sub": subject, "exp": expire, "type": "access"}
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def create_refresh_token(subject: str) -> Tuple[str, str]:
    """Create a refresh token and return both the token and its SHA-256 hash"""
    expire = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode = {"sub": subject, "exp": expire, "type": "refresh"}
    token = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    return token, token_hash

def verify_token(token: str, token_type: str = "access") -> Optional[str]:
    """
    Verify a JWT token.
    Returns the subject (user_id) if valid, None otherwise.
    Uses hmac.compare_digest for timing attack protection.
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        if payload.get("type") != token_type:
            return None
        # Timing-safe comparison for expiration check
        exp = payload.get("exp")
        if exp and datetime.fromtimestamp(exp, tz=timezone.utc) < datetime.now(timezone.utc):
            return None
        return payload.get("sub")
    except JWTError:
        return None

def verify_token_side_by_side(refresh_token: str, stored_hash: str) -> bool:
    """Timing-safe comparison of a refresh token against its stored hash"""
    computed_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    return hmac.compare_digest(computed_hash, stored_hash)

def generate_reset_token() -> str:
    """Generate a cryptographically secure one-time password reset token"""
    return secrets.token_urlsafe(32)

def hash_reset_token(token: str) -> str:
    """Hash a reset token for storage (SHA-256)"""
    return hashlib.sha256(token.encode()).hexdigest()