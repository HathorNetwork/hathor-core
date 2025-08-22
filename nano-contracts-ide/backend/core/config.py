"""
Configuration settings for the Nano Contracts IDE Backend
"""
from functools import lru_cache
from typing import Optional
from pydantic import BaseSettings


class Settings(BaseSettings):
    """Application settings"""

    # Application
    app_name: str = "Nano Contracts IDE"
    debug: bool = True
    environment: str = "development"

    # API
    api_host: str = "0.0.0.0"
    api_port: int = 8000

    # Security
    secret_key: str = "dev-secret-key-change-in-production"

    # Nano Contracts
    nc_initial_fuel: int = 1000000
    nc_memory_limit: int = 100 * 1024 * 1024  # 100MB
    nc_max_code_size: int = 1024 * 1024  # 1MB
    nc_max_recursion_depth: int = 100
    nc_max_call_counter: int = 250

    # Storage
    redis_url: str = "redis://localhost:6379"
    storage_type: str = "memory"  # "memory" or "redis"

    # Network
    hathor_network: str = "testnet"  # "mainnet", "testnet", "localnet"
    hathor_node_url: Optional[str] = None

    # Development
    auto_reload: bool = True
    log_level: str = "info"

    class Config:
        env_file = ".env"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance"""
    return Settings()
