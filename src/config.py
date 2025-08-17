"""Configuration management module."""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """Application settings with environment variable support."""

    # Environment
    environment: str = Field(default="local", env="ENVIRONMENT")
    log_level: str = Field(default="INFO", env="LOG_LEVEL")

    # AWS Configuration
    aws_region: str = Field(default="eu-west-2", env="AWS_REGION")
    aws_account_id: str = Field(default="275057777261", env="AWS_ACCOUNT_ID")
    aws_profile: str = Field(default="default", env="AWS_PROFILE")

    # Lambda Configuration
    lambda_timeout: int = Field(default=300, env="LAMBDA_TIMEOUT")
    lambda_memory_size: int = Field(default=512, env="LAMBDA_MEMORY_SIZE")

    # Monitoring
    enable_metrics: bool = Field(default=True, env="ENABLE_METRICS")
    enable_tracing: bool = Field(default=True, env="ENABLE_TRACING")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


def load_config(config_path: Optional[Path] = None) -> Dict[str, Any]:
    """Load configuration from YAML file."""
    if config_path is None:
        config_path = (
            Path(__file__).parent.parent / "config" / "environments" / "local.yaml"
        )

    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with open(config_path, "r") as f:
        return yaml.safe_load(f)


# Global settings instance
settings = Settings()
