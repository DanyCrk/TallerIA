from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, EmailStr
from typing import List, Optional

class Settings(BaseSettings):
    # Database
    DATABASE_URL: str = Field(..., env="DATABASE_URL")
    
    # JWT
    SECRET_KEY: str = Field(..., env="SECRET_KEY", min_length=32)
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(15, env="ACCESS_TOKEN_EXPIRE_MINUTES")
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(7, env="REFRESH_TOKEN_EXPIRE_DAYS")
    
    # Password
    BCRYPT_ROUNDS: int = Field(12, env="BCRYPT_ROUNDS")
    RESET_TOKEN_EXPIRE_MINUTES: int = Field(30, env="RESET_TOKEN_EXPIRE_MINUTES")
    
    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = Field(10, env="RATE_LIMIT_PER_MINUTE")
    
    # Email
    SMTP_HOST: str = Field(..., env="SMTP_HOST")
    SMTP_PORT: int = Field(587, env="SMTP_PORT")
    SMTP_USER: str = Field(..., env="SMTP_USER")
    SMTP_PASSWORD: str = Field(..., env="SMTP_PASSWORD")
    SMTP_FROM_EMAIL: EmailStr = Field(..., env="SMTP_FROM_EMAIL")
    
    # General
    ENVIRONMENT: str = Field("development", env="ENVIRONMENT")
    CORS_ORIGINS: Optional[List[str]] = Field(None, env="CORS_ORIGINS")
    
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()