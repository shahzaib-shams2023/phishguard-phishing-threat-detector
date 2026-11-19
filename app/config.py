from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional


class Settings(BaseSettings):
    app_name: str = "PhishGuard Phishing Threat & Malicious URL Forensic Engine"
    host: str = "0.0.0.0"
    port: int = 8005
    environment: str = "development"

    phish_risk_threshold: float = 65.0

    llm_api_key: Optional[str] = None
    llm_base_url: str = "https://api.openai.com/v1"
    llm_model: str = "gpt-4o-mini"
    llm_temperature: float = 0.1

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()

