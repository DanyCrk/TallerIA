from pydantic import BaseModel, EmailStr, Field, field_validator
import re
from datetime import datetime
from uuid import UUID

# Password validation
PASSWORD_PATTERN = re.compile(
    r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
)

class RegisterRequest(BaseModel):
    email: EmailStr
    full_name: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=8)
    
    @field_validator("password")
    def validate_password(cls, v):
        if not PASSWORD_PATTERN.match(v):
            raise ValueError("Password must be at least 8 chars, include uppercase, lowercase, number, and special character")
        return v
    
    @field_validator("full_name")
    def validate_full_name(cls, v):
        if not v.strip():
            raise ValueError("Full name cannot be empty")
        return v.strip()

class UserResponse(BaseModel):
    id: UUID
    email: EmailStr
    full_name: str
    created_at: datetime
    
    class Config:
        from_attributes = True

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class RefreshRequest(BaseModel):
    refresh_token: str

class PasswordResetRequest(BaseModel):
    email: EmailStr

class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8)
    
    @field_validator("new_password")
    def validate_password(cls, v):
        if not PASSWORD_PATTERN.match(v):
            raise ValueError("Password must be at least 8 chars, include uppercase, lowercase, number, and special character")
        return v