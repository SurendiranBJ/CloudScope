import os
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    ENVIRONMENT: str = "development"
    AUTH_ENABLED: bool = False
    AUTH_REQUIRED: bool = False
    DEV_AUTH_MODE: bool = False
    
    JWT_SECRET: str = ""
    JWT_ALGORITHM: str = "HS256"
    
    OIDC_ISSUER_URL: str = ""
    OIDC_AUDIENCE: str = ""
    OIDC_JWKS_URL: str = ""

    DATABASE_URL: str = "sqlite:///./cloudscope.db"

    TRUSTED_PROXIES: str = ""

    LOG_FORMAT: str = "json"
    LOG_LEVEL: str = "INFO"

    APP_VERSION: str = "1.0.0"
    BUILD_VERSION: Optional[str] = None
    GIT_COMMIT: Optional[str] = None
    COMMIT_SHA: Optional[str] = None
    IMAGE_TAG: Optional[str] = None

    SCAN_LOCK_LEASE_SECONDS: int = 180
    SNAPSHOT_RETENTION_COUNT: int = 10
    AUDIT_RETENTION_DAYS: int = 90

    RATE_LIMIT_SCAN_MAX: int = 5
    RATE_LIMIT_SCAN_WINDOW: int = 600
    RATE_LIMIT_COPILOT_MAX: int = 30
    RATE_LIMIT_COPILOT_WINDOW: int = 60
    RATE_LIMIT_SIMULATION_MAX: int = 30
    RATE_LIMIT_SIMULATION_WINDOW: int = 60
    RATE_LIMIT_FINDING_MAX: int = 60
    RATE_LIMIT_FINDING_WINDOW: int = 60
    RATE_LIMIT_AUDIT_MAX: int = 60
    RATE_LIMIT_AUDIT_WINDOW: int = 60
    RATE_LIMIT_EXPORT_MAX: int = 20
    RATE_LIMIT_EXPORT_WINDOW: int = 60
    RATE_LIMIT_GENERAL_MAX: int = 300
    RATE_LIMIT_GENERAL_WINDOW: int = 60

    AWS_CREDENTIALS_DIR: str = "~/.aws"
    AWS_PROFILE: str = "identityscope-scanner"
    AWS_DEFAULT_REGION: str = "ap-south-1"
    SCAN_REGIONS: str = ""
    
    NEO4J_URI: str = "bolt://localhost:7687"
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: str = "password"
    
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    
    BACKEND_PORT: int = 8000
    SCAN_INTERVAL_MINUTES: int = 5
    
    CORS_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
    ]

    # AI Security Copilot Settings
    AI_PROVIDER: str = "gemini"
    GEMINI_API_KEY: Optional[str] = None
    GEMINI_MODEL: str = "gemini-3.5-flash"
    GEMINI_FALLBACK_MODELS: list[str] = ["gemini-flash-lite-latest", "gemini-3.8-flash"]
    AI_MAX_OUTPUT_TOKENS: int = 4096
    AI_TEMPERATURE: float = 0.2
    AI_CONTEXT_MAX_CHARS: int = 24000
    AI_TIMEOUT_SECONDS: int = 30

    model_config = SettingsConfigDict(
        env_file=(
            os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), ".env"),
            os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env")
        ),
        env_file_encoding="utf-8",
        extra="ignore"
    )

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT.lower() == "production"

settings = Settings()
