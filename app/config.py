from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "API Sentinel"
    api_v1_prefix: str = "/v1"

    database_url: str = "sqlite:///./api_sentinel.db"
    auto_create_schema: bool = True

    default_tenant_code: str = "default-bank"
    default_tenant_name: str = "Default Bank"

    auth_required: bool = False
    auth_allow_insecure_dev_tokens: bool = True
    auth_default_roles: str = "admin,analyst,approver,auditor"
    auth_default_user: str = "local-admin"
    auth_require_verified_jwt: bool = True
    auth_enforce_mapped_roles: bool = True
    auth_allowed_roles: str = "admin,analyst,approver,auditor"
    auth_role_aliases_json: str = "{}"
    auth_jwt_algorithms: str = "RS256"
    auth_jwks_url: str = ""

    keycloak_issuer: str = "http://keycloak:8080/realms/api-sentinel"
    keycloak_audience: str = "api-sentinel"

    connector_simulated_fallback: bool = True
    kong_admin_url: str = "http://kong:8001"
    kong_workspace: str = "default"

    github_api_base_url: str = "https://api.github.com"
    github_owner: str = ""
    github_repo: str = ""
    github_token: str = ""
    github_openapi_paths: str = "openapi.yaml,openapi.yml,docs/openapi.yaml"

    splunk_base_url: str = ""
    splunk_token: str = ""
    splunk_query: str = "search index=api_threats | head 20"

    ollama_base_url: str = "http://ollama:11434"
    ollama_model: str = "llama3.1:8b-instruct-q4_0"
    ollama_timeout_seconds: int = 30

    worker_poll_seconds: int = 2
    worker_name: str = "default-worker"

    # CORS & Rate-limiting
    cors_origins: str = "*"
    rate_limit_rps: int = 20
    rate_limit_burst: int = 50

    # Alerting
    alert_webhook_url: str = ""
    alert_email_to: str = ""

    model_config = SettingsConfigDict(env_prefix="SENTINEL_", env_file=".env", extra="ignore")


settings = Settings()
