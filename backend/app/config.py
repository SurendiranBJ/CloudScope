import os
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    AWS_PROFILE: str = "identityscope-scanner"
    AWS_DEFAULT_REGION: str = "ap-south-1"
    SCAN_REGIONS: str | None = None
    
    NEO4J_URI: str = "bolt://localhost:7687"
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: str = "password"
    
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    
    BACKEND_PORT: int = 8000
    SCAN_INTERVAL_MINUTES: int = 2
    LOG_LEVEL: str = "INFO"
    
    CORS_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
    ]

    model_config = SettingsConfigDict(
        env_file=os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), ".env"),
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()
