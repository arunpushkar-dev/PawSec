"""PawSec Server — Configuration (loaded from .env)"""

from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    pawsec_api_key: str = Field(default="dev-key-change-in-production", alias="PAWSEC_API_KEY")
    db_path: str = Field(default="./pawsec.db", alias="DB_PATH")
    host: str = Field(default="0.0.0.0", alias="HOST")
    port: int = Field(default=8000, alias="PORT")
    ollama_url: str = Field(default="http://localhost:11434/api/chat", alias="OLLAMA_URL")
    ollama_model: str = Field(default="qwen2.5-finetuned", alias="OLLAMA_MODEL")
    ollama_timeout: int = Field(default=10, alias="OLLAMA_TIMEOUT")
    cors_origins: str = Field(default="*", alias="CORS_ORIGINS")
    min_store_score: int = Field(default=0, alias="MIN_STORE_SCORE")
    admin_email: str = Field(default="admin@pawsec.local", alias="ADMIN_EMAIL")

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "populate_by_name": True}


settings = Settings()
