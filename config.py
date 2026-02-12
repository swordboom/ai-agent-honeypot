import os
from dataclasses import dataclass


def load_dotenv(path: str = ".env") -> None:
    """
    Minimal .env loader (no external dependency).

    - Only sets variables that are not already present in os.environ.
    - Supports KEY=VALUE, optional quotes, and ignores blank lines/comments.
    """
    try:
        if not os.path.exists(path):
            return
        with open(path, "r", encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.lower().startswith("export "):
                    line = line[7:].strip()
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                if not key or key in os.environ:
                    continue
                value = value.strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
                    value = value[1:-1]
                os.environ[key] = value
    except Exception:
        # Never break app startup because of a local dev convenience feature.
        return


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    try:
        return int(value)
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    api_key: str
    dashboard_key: str
    callback_url: str
    extended_response: bool

    openai_api_key: str
    openai_model: str
    gemini_api_key: str
    gemini_model: str

    agent_max_history_messages: int
    llm_timeout_seconds: int

    enable_llm_extraction: bool
    llm_extraction_min_interval_seconds: int

    session_ttl_seconds: int
    session_cleanup_interval_seconds: int

    callback_timeout_seconds: int
    callback_max_attempts: int
    callback_backoff_base_seconds: int
    callback_max_workers: int
    enable_callback_updates: bool
    callback_max_updates: int

    @staticmethod
    def from_env() -> "Settings":
        # Load local .env if present (Docker/Render will ignore due to .dockerignore / missing file).
        load_dotenv()
        return Settings(
            api_key=os.getenv("HONEY_POT_API_KEY") or os.getenv("API_KEY") or "dev-key",
            dashboard_key=os.getenv("HONEY_POT_DASHBOARD_KEY") or "",
            callback_url=os.getenv(
                "HONEY_POT_CALLBACK_URL",
                "https://hackathon.guvi.in/api/updateHoneyPotFinalResult",
            ),
            extended_response=_env_bool("HONEY_POT_EXTENDED_RESPONSE", False),
            openai_api_key=os.getenv("OPENAI_API_KEY") or "",
            openai_model=os.getenv("OPENAI_MODEL") or "gpt-4o-mini",
            gemini_api_key=os.getenv("GEMINI_API_KEY") or "",
            gemini_model=os.getenv("GEMINI_MODEL") or "gemini-1.5-flash",
            agent_max_history_messages=_env_int("AGENT_MAX_HISTORY_MESSAGES", 12),
            llm_timeout_seconds=_env_int("LLM_TIMEOUT_SECONDS", 10),
            enable_llm_extraction=_env_bool("ENABLE_LLM_EXTRACTION", True),
            llm_extraction_min_interval_seconds=_env_int("LLM_EXTRACTION_MIN_INTERVAL_SECONDS", 15),
            session_ttl_seconds=_env_int("SESSION_TTL_SECONDS", 6 * 60 * 60),
            session_cleanup_interval_seconds=_env_int("SESSION_CLEANUP_INTERVAL_SECONDS", 60),
            callback_timeout_seconds=_env_int("CALLBACK_TIMEOUT_SECONDS", 5),
            callback_max_attempts=_env_int("CALLBACK_MAX_ATTEMPTS", 3),
            callback_backoff_base_seconds=_env_int("CALLBACK_BACKOFF_BASE_SECONDS", 1),
            callback_max_workers=_env_int("CALLBACK_MAX_WORKERS", 4),
            enable_callback_updates=_env_bool("ENABLE_CALLBACK_UPDATES", True),
            callback_max_updates=_env_int("CALLBACK_MAX_UPDATES", 2),
        )
