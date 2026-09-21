"""Application configuration loaded from environment variables."""

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_ROOT = Path(__file__).resolve().parents[2]
PROJECT_ROOT = BACKEND_ROOT.parent


class Settings(BaseSettings):
    """Central settings for database and application configuration."""

    model_config = SettingsConfigDict(
        env_file=(
            BACKEND_ROOT / ".env",
            PROJECT_ROOT / ".env",
            ".env",
        ),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    environment: str = Field(default="development", alias="ENVIRONMENT")
    project_name: str = Field(default="IoT Security Framework", alias="PROJECT_NAME")

    database_url: str = Field(
        default="postgresql+psycopg://postgres:CHANGE_ME@localhost:5432/iot_security",
        alias="DATABASE_URL",
    )

    # Used only by create_database.py to connect to the default postgres database.
    postgres_admin_url: str = Field(
        default="postgresql+psycopg://postgres:CHANGE_ME@localhost:5432/postgres",
        alias="POSTGRES_ADMIN_URL",
    )

    api_host: str = Field(default="127.0.0.1", alias="API_HOST")
    api_port: int = Field(default=8000, alias="API_PORT")

    # MQTT broker (lab evidence target for findings/risk APIs)
    mqtt_broker_host: str = Field(default="127.0.0.1", alias="MQTT_BROKER_HOST")
    mqtt_broker_port: int = Field(default=1883, alias="MQTT_BROKER_PORT")
    mqtt_tls_enabled: bool = Field(default=False, alias="MQTT_TLS_ENABLED")
    mqtt_anonymous_allowed: bool = Field(default=True, alias="MQTT_ANONYMOUS_ALLOWED")
    mqtt_service_name: str = Field(default="mosquitto", alias="MQTT_SERVICE_NAME")
    mqtt_service_version: str = Field(default="2.1.2", alias="MQTT_SERVICE_VERSION")
    mqtt_observed_topics: str = Field(
        default="iot/esp32/01/sensor,iot/esp32/02/sensor",
        alias="MQTT_OBSERVED_TOPICS",
    )

    # Default IoT context used by GET /api/v1/risk (overridable via env)
    risk_device_criticality: float = Field(default=0.3, alias="RISK_DEVICE_CRITICALITY")
    risk_network_exposure: float = Field(default=0.3, alias="RISK_NETWORK_EXPOSURE")
    risk_firmware_security: float = Field(default=0.5, alias="RISK_FIRMWARE_SECURITY")

    # Devices are ONLINE only while valid telemetry is fresher than this window.
    device_offline_after_seconds: int = Field(
        default=30,
        alias="DEVICE_OFFLINE_AFTER_SECONDS",
    )

    # Local Ollama AI explanation layer (optional; rule-based fallback always available)
    ollama_base_url: str = Field(
        default="http://localhost:11434",
        alias="OLLAMA_BASE_URL",
    )
    ollama_model: str = Field(
        default="qwen3:8b",
        alias="OLLAMA_MODEL",
    )
    # Local qwen3:8b often needs >60s on CPU/GPU-shared hosts; override via env.
    ollama_timeout: int = Field(
        default=180,
        alias="OLLAMA_TIMEOUT",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
