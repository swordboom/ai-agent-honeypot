import os
from dataclasses import dataclass

from agent.llm_clients import DEFAULT_FREE_MODELS


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


def _env_list(name: str, default: tuple) -> tuple:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    models = tuple(m.strip() for m in value.split(",") if m.strip())
    return models or default


@dataclass(frozen=True)
class Settings:
    api_key: str
    extended_response: bool

    openrouter_api_key: str
    openrouter_models: tuple

    agent_max_history_messages: int
    llm_timeout_seconds: int
    request_timeout_budget_seconds: int
    enable_llm_behavior_analysis: bool
    high_load_mode: bool
    llm_global_rpm_limit: int
    llm_reply_rpm_limit: int
    llm_behavior_rpm_limit: int
    llm_extraction_rpm_limit: int
    llm_behavior_sample_every_n_scam_messages: int

    enable_llm_extraction: bool
    llm_extraction_min_interval_seconds: int
    inactivity_finalize_seconds: int

    session_ttl_seconds: int
    session_cleanup_interval_seconds: int


    @staticmethod
    def from_env() -> "Settings":
        # Load local .env if present (Docker/Render will ignore due to .dockerignore / missing file).
        load_dotenv()
        return Settings(
            api_key=os.getenv("HONEY_POT_API_KEY") or os.getenv("API_KEY") or "",
            extended_response=_env_bool("HONEY_POT_EXTENDED_RESPONSE", False),
            openrouter_api_key=os.getenv("OPENROUTER_API_KEY") or "",
            openrouter_models=_env_list("OPENROUTER_MODELS", DEFAULT_FREE_MODELS),
            agent_max_history_messages=_env_int("AGENT_MAX_HISTORY_MESSAGES", 12),
            llm_timeout_seconds=_env_int("LLM_TIMEOUT_SECONDS", 12),
            request_timeout_budget_seconds=_env_int("REQUEST_TIMEOUT_BUDGET_SECONDS", 26),
            enable_llm_behavior_analysis=_env_bool("ENABLE_LLM_BEHAVIOR_ANALYSIS", True),
            high_load_mode=_env_bool("HIGH_LOAD_MODE", False),
            llm_global_rpm_limit=_env_int("LLM_GLOBAL_RPM_LIMIT", 26),
            llm_reply_rpm_limit=_env_int("LLM_REPLY_RPM_LIMIT", 18),
            llm_behavior_rpm_limit=_env_int("LLM_BEHAVIOR_RPM_LIMIT", 8),
            llm_extraction_rpm_limit=_env_int("LLM_EXTRACTION_RPM_LIMIT", 6),
            llm_behavior_sample_every_n_scam_messages=_env_int(
                "LLM_BEHAVIOR_SAMPLE_EVERY_N_SCAM_MESSAGES",
                2,
            ),
            enable_llm_extraction=_env_bool("ENABLE_LLM_EXTRACTION", True),
            llm_extraction_min_interval_seconds=_env_int("LLM_EXTRACTION_MIN_INTERVAL_SECONDS", 15),
            inactivity_finalize_seconds=_env_int("INACTIVITY_FINALIZE_SECONDS", 120),
            session_ttl_seconds=_env_int("SESSION_TTL_SECONDS", 6 * 60 * 60),
            session_cleanup_interval_seconds=_env_int("SESSION_CLEANUP_INTERVAL_SECONDS", 60),
        )
