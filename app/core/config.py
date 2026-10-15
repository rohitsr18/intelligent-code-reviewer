from functools import lru_cache
from typing import List, Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "24/7 Intelligent Code Reviewer"
    app_version: str = Field(default="1.0.0", alias="APP_VERSION")
    environment: str = Field(default="development", alias="ENVIRONMENT")
    port: int = Field(default=8080, alias="PORT")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    debug: bool = False

    # GCP & Vertex / Gemini
    gcp_project_id: str = Field(default="local-dev-project", alias="GCP_PROJECT_ID")
    gcp_location: str = Field(default="us-central1", alias="GCP_LOCATION")
    gemini_model: str = Field(default="gemini-1.5-pro", alias="GEMINI_MODEL")
    gemini_temperature: float = Field(default=0.2, alias="GEMINI_TEMPERATURE")
    gemini_max_output_tokens: int = Field(default=8192, alias="GEMINI_MAX_OUTPUT_TOKENS")

    # BigQuery datasets & tables
    bq_dataset_id: str = Field(default="code_reviewer_analytics", alias="BQ_DATASET_ID")
    bq_rules_table: str = Field(default="historical_rules", alias="BQ_RULES_TABLE")
    bq_reviews_table: str = Field(default="review_events", alias="BQ_REVIEWS_TABLE")

    # Firestore collections
    firestore_collection_reviews: str = Field(
        default="reviews", alias="FIRESTORE_COLLECTION_REVIEWS"
    )
    firestore_collection_users: str = Field(default="users", alias="FIRESTORE_COLLECTION_USERS")
    firestore_collection_sessions: str = Field(
        default="sessions", alias="FIRESTORE_COLLECTION_SESSIONS"
    )

    # IAP Auth
    iap_enabled: bool = Field(default=False, alias="IAP_ENABLED")
    iap_audience: Optional[str] = Field(default=None, alias="IAP_AUDIENCE")

    # Sanitization & Guardrails
    secret_scanning_enabled: bool = Field(default=True, alias="SECRET_SCANNING_ENABLED")
    pii_redaction_enabled: bool = Field(default=True, alias="PII_REDACTION_ENABLED")
    prompt_injection_defense_enabled: bool = Field(
        default=True, alias="PROMPT_INJECTION_DEFENSE_ENABLED"
    )
    entropy_threshold: float = Field(default=4.5, alias="ENTROPY_THRESHOLD")
    # Access control & limits
    admin_emails: List[str] = ["admin@company.com"]
    max_code_size_bytes: int = Field(default=500_000, alias="MAX_CODE_SIZE_BYTES")
    max_code_lines: int = Field(default=5000, alias="MAX_CODE_LINES")
    rate_limit_per_minute: int = Field(default=60, alias="RATE_LIMIT_PER_MINUTE")

    allowed_cors_origins: List[str] = ["*"]


@lru_cache()
def get_settings() -> Settings:
    return Settings()
