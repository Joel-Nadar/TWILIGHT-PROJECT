"""
Configuration loader for Twilight Gateway.
Loads .env file into a typed settings object.
"""
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional


class Settings(BaseSettings):
    """Gateway configuration settings"""
    
    # Gateway server
    gateway_host: str = "127.0.0.1"
    gateway_port: int = 8000
    
    # Database
    db_path: str = "data/twilight.db"
    
    # Mode settings
    fail_mode: str = "closed"  # "closed" or "open"
    demo_mode: bool = True
    runtime_mode: str = "on"  # "off", "dry-run", "on"
    
    # Security
    gateway_api_key: str = "change-me"
    
    # Attestation
    timestamp_window_sec: int = 30
    
    # Trust thresholds
    trust_healthy_min: int = 70
    trust_flag_min: int = 40
    trust_throttle_min: int = 20
    trust_recovery_per_min: float = 1.0
    trust_hysteresis: int = 5
    
    # Probation
    probation_start_score: int = 60
    probation_cap: int = 80
    probation_clean_min: int = 10
    
    # Rate limiting
    rate_window_sec: int = 60
    rate_halt_after_violations: int = 5
    
    # Audit
    audit_checkpoint_every: int = 10
    
    # Heartbeat
    heartbeat_interval_sec: int = 10
    heartbeat_challenge_expire_sec: int = 30
    
    # HOLD queue
    hold_timeout_sec: int = 300
    hold_sweep_interval_sec: int = 10
    
    # Trust recovery
    trust_recovery_interval_sec: int = 60
    
    # Drift detection (W2)
    drift_zscore_threshold: float = 3.0
    
    # Timeouts
    pipeline_timeout_sec: int = 30
    tool_timeout_sec: int = 10
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False
    )


# Global settings instance
settings = Settings()
