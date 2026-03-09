import os

class Settings:
    database_url: str = os.getenv("DATABASE_URL", "postgresql+asyncpg://offensecops_user:changeme@postgres:5432/offensecops")
    redis_url: str = os.getenv("REDIS_URL", "redis://:changeme@redis:6379/0")
    jwt_secret_key: str = os.getenv("JWT_SECRET_KEY", "your-jwt-secret-key-min-32-chars-here")
    jwt_algorithm: str = os.getenv("JWT_ALGORITHM", "HS256")
    access_token_expire_minutes: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
    refresh_token_expire_days: int = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
    docker_socket: str = os.getenv("DOCKER_SOCKET", "/var/run/docker.sock")
    scan_output_dir: str = os.getenv("SCAN_OUTPUT_DIR", "/app/scan_outputs")
    environment: str = os.getenv("ENVIRONMENT", "development")

settings = Settings()
