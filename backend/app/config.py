"""Application settings, read from environment variables / .env (never hard-code secrets)."""

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEV_JWT_SECRET = "dev-only-jwt-secret-change-me-0123456789abcdef"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    environment: str = Field("development", alias="ENVIRONMENT")

    # Database
    database_url: str = Field(
        "postgresql+psycopg://consentledger:consentledger@localhost:5432/consentledger",
        alias="DATABASE_URL",
    )
    # Non-owner role every request runs as, so row-level security applies
    db_app_role: str = Field("consentledger_app", alias="DB_APP_ROLE")
    # pgcrypto key for encrypted dataset fields
    encryption_key: str = Field("dev-only-encryption-key-change-me", alias="ENCRYPTION_KEY")

    # JWT
    jwt_secret: str = Field(DEV_JWT_SECRET, alias="JWT_SECRET")
    jwt_algorithm: str = Field("HS256", alias="JWT_ALGORITHM")
    jwt_expire_minutes: int = Field(60, alias="JWT_EXPIRE_MINUTES", ge=5, le=24 * 60)

    # Cookies
    cookie_secure: bool = Field(False, alias="COOKIE_SECURE")
    cookie_samesite: str = Field("lax", alias="COOKIE_SAMESITE")

    # Google OAuth 2.0
    google_client_id: str = Field("", alias="GOOGLE_CLIENT_ID")
    google_client_secret: str = Field("", alias="GOOGLE_CLIENT_SECRET")
    google_redirect_uri: str = Field(
        "http://localhost:5173/api/auth/google/callback", alias="GOOGLE_REDIRECT_URI"
    )

    # Local email/password login (bcrypt) for demo accounts
    allow_password_login: bool = Field(True, alias="ALLOW_PASSWORD_LOGIN")
    # Failed password logins allowed per email and client address in the window
    login_max_failures: int = Field(5, alias="LOGIN_MAX_FAILURES", ge=1)
    login_failure_window_seconds: int = Field(900, alias="LOGIN_FAILURE_WINDOW_SECONDS", ge=1)

    # Frontend / CORS
    frontend_url: str = Field("http://localhost:5173", alias="FRONTEND_URL")
    cors_origins: str = Field("http://localhost:5173,http://localhost:3000", alias="CORS_ORIGINS")

    @field_validator("cookie_samesite")
    @classmethod
    def _samesite(cls, v: str) -> str:
        v = v.lower()
        if v not in ("lax", "strict", "none"):
            raise ValueError("COOKIE_SAMESITE must be lax, strict or none")
        return v

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def google_enabled(self) -> bool:
        return bool(self.google_client_id)

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"

    def check_production_secrets(self) -> None:
        if self.is_production:
            if self.jwt_secret == DEV_JWT_SECRET or len(self.jwt_secret) < 32:
                raise RuntimeError("Set a strong JWT_SECRET (32+ chars) in production")
            if self.encryption_key.startswith("dev-only"):
                raise RuntimeError("Set ENCRYPTION_KEY in production")
            if not self.cookie_secure:
                raise RuntimeError("COOKIE_SECURE must be true in production")


@lru_cache
def get_settings() -> Settings:
    return Settings()
