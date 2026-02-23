from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "PhishGuard AI Enterprise"
    environment: str = "development"
    jwt_secret: str = "change-me"
    jwt_algorithm: str = "HS256"
    jwt_exp_minutes: int = 60
    database_url: str = "postgresql://phishguard:phishguard@db:5432/phishguard"
    redis_url: str = "redis://redis:6379/0"
    google_safe_browsing_api_key: str = ""
    trusted_brands: str = "paypal,visa,mastercard,chase,bankofamerica,stripe"
    model_path: str = "backend/ml/models/phishing_model.joblib"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


settings = Settings()
