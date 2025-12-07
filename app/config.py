"""
Configuration Management Module (refactored)

- Environment-aware validation centralized in Settings model_validator.
- Case-insensitive EnvironmentEnum parsing.
- Safer production checks for secrets, HTTPS/HSTS, and SMTP credentials.
- Warnings instead of prints inside validators.
- Normalized plan keys while preserving legacy shapes.
"""

import json
import os
import warnings
from enum import Enum
from functools import lru_cache
from typing import Dict, Optional, List, Set, Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    RedisDsn,
    SecretStr,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.validations.temp_mail_domains import DISPOSABLE_DOMAINS as STATIC_DISPOSABLE_DOMAINS


SAFE_CONTENT_TYPES = [
    "application/json",
    "multipart/form-data",
    "application/x-www-form-urlencoded",
]

class EnvironmentEnum(str, Enum):
    """Application environment types"""
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    TESTING = "testing"


class RateLimitTier(BaseModel):
    """Rate limiting configuration tier"""
    requests: int = Field(default=100, description="Number of requests allowed in the time window", ge=1)
    window: int = Field(default=3600, description="Time window in seconds", ge=1)
    burst: int = Field(default=20, description="Burst capacity for rate limiting", ge=1)

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class SecuritySettings(BaseSettings):
    """Security-related configuration"""
    cors_origins: List[str] = Field(
        default=["http://localhost:5173", "http://localhost:8000"],
        description="Allowed CORS origins",
    )
    https_redirect: bool = Field(
        default=True,
        description="Enforce HTTPS redirects in production",
    )
    hsts_max_age: int = Field(
        default=63072000,  # 2 years
        description="HSTS max-age header value in seconds",
        ge=0,
    )
    webhook_secret: SecretStr = Field(
        ...,  # ❌ NO DEFAULT - Must be provided
        description="HMAC secret for webhook verification",
        alias="SECURITY_WEBHOOK_SECRET"
    )
    allowed_hosts: List[str] = Field(
        default=["localhost", "127.0.0.1"],
        description="Allowed host headers for security",
    )

    @model_validator(mode="after")
    def validate_production_secrets(self) -> "SecuritySettings":
        """Enforce strong secrets in production"""
        # We can't easily check environment here as it's in parent Settings, 
        # but we can ensure the value is not a placeholder if provided.
        secret = self.webhook_secret.get_secret_value()
        if secret == "test_webhook_secret" or len(secret) < 16:
             # In a real scenario we might raise ValueError, but to avoid breaking dev:
             warnings.warn("Weak webhook_secret detected. Use a strong secret in production.")
        return self

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: Any) -> List[str]:
        """Parse CORS origins from string or list"""
        if isinstance(v, str):
            try:
                return json.loads(v)
            except json.JSONDecodeError:
                return [origin.strip() for origin in v.split(",") if origin.strip()]
        if isinstance(v, list):
            return v
        raise ValueError("CORS origins must be a list or JSON string")

    @field_validator("https_redirect", mode="before")
    @classmethod
    def validate_https_redirect(cls, v: Any) -> bool:
        """Validate and convert HTTPS redirect flag"""
        if isinstance(v, bool):
            return v
        if isinstance(v, str):
            v_lower = v.lower()
            if v_lower in {"true", "1", "yes", "on"}:
                return True
            if v_lower in {"false", "0", "no", "off"}:
                return False
        raise ValueError(f"Invalid boolean value for https_redirect: {v}")

    model_config = SettingsConfigDict(
        env_prefix="SECURITY_",
        env_file=".env",
        extra="ignore",
        case_sensitive=False,
    )



class EmailValidationSettings(BaseSettings):
    """Email validation service configuration"""

    # Detectar Docker automáticamente
    skip_external_validation: bool = Field(
        default_factory=lambda: os.getenv("DOCKER_ENV") == "1",
        description="Skip external DNS/SMTP in Docker environments"
    )
    
    # DNS/MX core
    mx_lookup_timeout: float = Field(default=2.0, gt=0, le=30.0, description="DNS MX lookup timeout in seconds")
    dns_timeout: float = Field(default=2.0, gt=0, le=30.0, description="Generic DNS resolver timeout in seconds")
    dns_nameservers: List[str] = Field(default_factory=list, description="Override resolver nameservers")
    mx_limit: int = Field(default=10, ge=1, le=50, description="Max MX records to consider")

    # Retries/backoff
    retry_base_backoff: float = Field(default=0.25, ge=0.0, le=10.0, description="Base backoff for retries")
    retry_max_backoff: float = Field(default=2.0, ge=0.0, le=60.0, description="Max backoff for retries")
    max_retries: int = Field(default=3, ge=1, le=10, description="Max SMTP/DNS retries")

    # SMTP
    smtp_timeout: float = Field(default=5.0, gt=0, le=30.0, description="SMTP connection timeout in seconds")
    smtp_ports: List[int] = Field(default=[587, 465, 25], description="SMTP ports to try in order")
    smtp_use_tls: bool = Field(default=True, description="Use TLS for SMTP connections")

    # Features
    advanced_mx_check: bool = Field(default=True, description="Enable advanced MX record checking")
    cache_ttl: int = Field(default=3600, ge=60, description="TTL for DNS and validation cache in seconds")
    idn_support: bool = Field(default=True, description="Enable internationalized domain names (IDN) support")
    disposable_domains: Set[str] = Field(default_factory=lambda: STATIC_DISPOSABLE_DOMAINS, description="Known disposable email domains")

    @field_validator("disposable_domains", mode="before")
    @classmethod
    def parse_disposable_domains(cls, v: Any) -> Set[str]:
        if isinstance(v, str):
            parsed = json.loads(v)
            if not isinstance(parsed, list):
                raise ValueError("Expected a list of domains")
            return set(parsed)
        if isinstance(v, set):
            return v
        if isinstance(v, list):
            return set(v)
        return STATIC_DISPOSABLE_DOMAINS

    @field_validator("smtp_ports", mode="before")
    @classmethod
    def validate_smtp_ports(cls, v: Any) -> List[int]:
        if isinstance(v, str):
            ports = json.loads(v)
            if not isinstance(ports, list):
                raise ValueError("SMTP ports must be a list")
            return [int(port) for port in ports]
        return v

    @field_validator("dns_nameservers", mode="before")
    @classmethod
    def _parse_dns_nameservers(cls, v: Any) -> List[str]:
        if isinstance(v, str):
            try:
                arr = json.loads(v)
                if not isinstance(arr, list):
                    raise ValueError("dns_nameservers must be a list")
                return [str(x).strip() for x in arr if str(x).strip()]
            except json.JSONDecodeError:
                return [s.strip() for s in v.split(",") if s.strip()]
        if isinstance(v, list):
            return [str(x).strip() for x in v if str(x).strip()]
        return []

    model_config = SettingsConfigDict(env_prefix="VALIDATION_", env_file=".env", extra="ignore")


class DynamicQuotaSettings(BaseSettings):
    """Dynamic quota adjustment configuration"""
    threshold_percent: float = Field(default=0.8, ge=0.1, le=0.95, description="Usage threshold (0-1) for dynamic quota")
    adjustment_factor: float = Field(default=1.2, ge=1.0, le=3.0, description="Multiplier for quota increases")
    max_adjustments: int = Field(default=5, ge=1, description="Maximum automatic adjustments")
    cooldown_hours: int = Field(default=24, ge=1, description="Hours between automatic adjustments")

    model_config = SettingsConfigDict(env_prefix="QUOTA_", env_file=".env", extra="ignore")


class StripeSettings(BaseSettings):
    """Stripe payment processing configuration"""
    
    secret_key: SecretStr = Field(
        default=SecretStr("sk_test_dummy"),
        description="Stripe secret key",
        alias="STRIPE_SECRET_KEY"
    )
    public_key: SecretStr = Field(
        default=SecretStr("pk_test_dummy"),
        description="Stripe public key",
        alias="STRIPE_PUBLIC_KEY"
    )
    webhook_secret: SecretStr = Field(
        default=SecretStr("whsec_dummy"),
        description="Stripe webhook secret",
        alias="STRIPE_WEBHOOK_SECRET"
    )
    premium_plan_id: str = Field(
        default="price_test_premium",
        description="Stripe Premium Plan price ID",
        alias="STRIPE_PREMIUM_PLAN_ID"
    )
    enterprise_plan_id: str = Field(
        default="price_test_enterprise",
        description="Stripe Enterprise Plan price ID",
        alias="STRIPE_ENTERPRISE_PLAN_ID"
    )
    success_url: str = Field(
        default="http://localhost:5173/dashboard/billing/success",
        description="Stripe success redirect URL",
        alias="STRIPE_SUCCESS_URL",
    )
    cancel_url: str = Field(
        default="http://localhost:5173/dashboard/billing",
        description="Stripe cancel redirect URL",
        alias="STRIPE_CANCEL_URL",
    )
    
    @field_validator("secret_key", mode="after")
    @classmethod
    def validate_stripe_key(cls, v: SecretStr) -> SecretStr:
        """Validate Stripe key format"""
        import os
        
        # En modo testing, permitir claves dummy
        if os.getenv("TESTING") == "1":
            return v
            
        key = v.get_secret_value()
        if key and key != "sk_test_dummy" and not key.startswith(("sk_test_", "sk_live_")):
            raise ValueError("Invalid Stripe key format. Must start with 'sk_test_' or 'sk_live_'")
        return v
    
    @field_validator("public_key", mode="after")
    @classmethod
    def validate_public_key(cls, v: SecretStr) -> SecretStr:
        """Validate Stripe public key format"""
        import os
        
        # En modo testing, permitir claves dummy
        if os.getenv("TESTING") == "1":
            return v
            
        key = v.get_secret_value()
        if key and key != "pk_test_dummy" and not key.startswith(("pk_test_", "pk_live_")):
            raise ValueError("Invalid Stripe public key format. Must start with 'pk_test_' or 'pk_live_'")
        return v
    
    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
        case_sensitive=False
    )

class JWTSettings(BaseSettings):
    secret: SecretStr = Field(default=SecretStr(""), description="JWT HMAC secret (HS*)", alias="JWT_SECRET")
    issuer: str = Field(default="email-validation-api", alias="JWT_ISSUER")
    audience: str = Field(default="email-validation-app", alias="JWT_AUDIENCE")
    access_token_expire_minutes: int = Field(default=15, ge=1, le=1440)
    refresh_token_expire_days: int = Field(default=30, ge=1, le=365)
    algorithm: str = Field(default="RS256", description="JWT signing algorithm, e.g. RS256 or HS256")

    # Asymmetric keys + rotation
    active_kid: str = Field(default="k1", description="Active key id for signing", alias="JWT_ACTIVE_KID")
    private_key_pem: SecretStr = Field(default=SecretStr(""), description="PEM for RS/ES private key", alias="JWT_PRIVATE_KEY_PEM")
    public_keys: Dict[str, str] = Field(default_factory=dict, description="Map kid -> PEM public key", alias="JWT_PUBLIC_KEYS_JSON")

    @field_validator("public_keys", mode="before")
    @classmethod
    def parse_public_keys(cls, v: Any) -> Dict[str, str]:
        if isinstance(v, str):
            data = json.loads(v)
            if not isinstance(data, dict):
                raise ValueError("JWT_PUBLIC_KEYS_JSON must be a JSON object {kid: pem}")
            return {str(k): str(pem) for k, pem in data.items()}
        if isinstance(v, dict):
            return {str(k): str(pem) for k, pem in v.items()}
        return {}

    @model_validator(mode="after")
    def validate_keys_by_algorithm(self) -> "JWTSettings":
        alg = (self.algorithm or "").upper()
        if alg.startswith("HS"):
            if not self.secret.get_secret_value():
                raise ValueError("JWT_SECRET required for HS* algorithms")
        else:
            if not self.private_key_pem.get_secret_value():
                raise ValueError("JWT_PRIVATE_KEY_PEM required for asymmetric algorithms")
            if not self.public_keys or self.active_kid not in self.public_keys:
                raise ValueError("JWT_PUBLIC_KEYS_JSON must include the active kid")
        return self
    
    model_config = SettingsConfigDict(
        env_prefix="JWT_",
        env_file=".env",
        extra="allow",
        populate_by_name=True,
    )

class APIDocumentationSettings(BaseSettings):
    """API documentation and UI configuration"""
    enabled: bool = Field(default=True, description="Enable API documentation endpoints")
    user: str = Field(default="admin", min_length=1, description="Docs basic auth user", alias="DOCS_USER")
    password: SecretStr = Field(
        default=SecretStr("test_docs_password"),
        description="Docs basic auth password",
        alias="DOCS_PASSWORD"
    )
    favicon_url: Optional[str] = Field(default="/static/favicon.ico", description="Swagger favicon")
    title: str = Field(default="Email Validation API — Enterprise-grade Email Verification", description="API title")
    version: str = Field(default="2.5.0", description="API version")
    description: str = Field(
        default=(
            "API robusta y segura para validación y verificación de correos electrónicos.\n"
            "Soporta verificación individual y en lote, detección de brechas, y autenticación JWT.\n"
            "Cumple con GDPR y dispone de planes de pago flexibles.\n\n"
            "**🔗 Enlaces importantes:**\n"
            "- [Estado del sistema](https://mailsafepro.betteruptime.com)\n"
            "- [Documentación completa](https://email-validation-api-jlra.onrender.com/redoc)\n\n"
            "**📧 Contacto:** mailsafepro1@gmail.com"
        ),
        description="API description"
    )
    contact: Dict[str, str] = Field(
        default={
            "name": "MailSafePro Support",
            "email": "mailsafepro1@gmail.com",
            "url": "https://mailsafepro.betteruptime.com"
        },
        description="API contact",
    )

    model_config = SettingsConfigDict(env_prefix="DOCS_", env_file=".env", extra="ignore")


class MonitoringSettings(BaseSettings):
    """Monitoring and observability configuration"""
    sentry_dsn: Optional[SecretStr] = Field(default=None, description="Sentry DSN for error tracking")
    metrics_enabled: bool = Field(default=True, description="Enable metrics collection")
    health_check_path: str = Field(default="/health", description="Health check endpoint path")
    log_level: str = Field(default="INFO", description="Application log level")
    enable_performance_metrics: bool = Field(default=True, description="Enable performance metrics collection")

    @field_validator("log_level", mode="before")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Validate log level value"""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in valid_levels:
            raise ValueError(f"Log level must be one of {valid_levels}")
        return v.upper()

    model_config = SettingsConfigDict(env_prefix="MONITORING_", env_file=".env", extra="ignore")


class Settings(BaseSettings):
    """
    Main application settings configuration

    Centralizes all configuration with environment-specific defaults,
    robust validation, and security best practices.
    """
    # Core Application Settings
    environment: EnvironmentEnum = Field(default=EnvironmentEnum.PRODUCTION, description="Application environment")
    debug: bool = Field(default=False, description="Enable debug mode")
    testing_mode: bool = Field(default=False, description="Enable testing-specific behaviors")

    # API Configuration
    api_key_secret: SecretStr = Field(
        default=SecretStr("a" * 32),  # AGREGAR default
        description="API key generation secret",
        alias="API_KEY_SECRET"
    )
    vt_api_key: SecretStr = Field(
        default=SecretStr("test_vt_key"),  # AGREGAR default
        description="VirusTotal API key",
        alias="VT_API_KEY"
    )
    clearbit_api_key: SecretStr = Field(
        default=SecretStr("test_clearbit_key"),  # AGREGAR default
        description="Clearbit API key",
        alias="CLEARBIT_API_KEY"
    )
    metrics_api_key: SecretStr = Field(
        default=SecretStr("test_metrics_key"),  # AGREGAR default
        description="API key for metrics endpoint",
        alias="API_KEY_METRICS"
    )

    # Service Configuration
    redis_url: RedisDsn = Field(default="redis://localhost:6379/0", description="Redis connection URL", alias="REDIS_URL")
    frontend_url: str = Field(default="http://localhost:5173", description="Base URL for frontend", alias="FRONTEND_URL")

    # SMTP Configuration
    smtp_host: str = Field(default="localhost", description="SMTP server host", alias="SMTP_HOST")
    smtp_port: int = Field(default=587, ge=1, le=65535, description="SMTP server port", alias="SMTP_PORT")
    smtp_username: str = Field(default="", description="SMTP auth username", alias="SMTP_USERNAME")
    smtp_password: SecretStr = Field(default=SecretStr(""), description="SMTP auth password", alias="SMTP_PASSWORD")
    from_email: str = Field(default="noreply@example.com", description="Default sender email", alias="FROM_EMAIL")
    from_name: str = Field(default="Email Validation API", description="Default sender name", alias="FROM_NAME")

    # Feature Flags
    enable_test_routes: bool = Field(default=False, description="Include test routes in Swagger", alias="ENABLE_TEST_ROUTES")
    enable_premium_features: bool = Field(default=False, description="Enable premium feature endpoints")

    # Rate Limiting Configuration (two shapes preserved for compatibility)
    rate_limits: Dict[str, RateLimitTier] = Field(
        default_factory=lambda: {
            "free": RateLimitTier(requests=100, window=3600, burst=20),
            "startup": RateLimitTier(requests=5000, window=3600, burst=100),
            "enterprise": RateLimitTier(requests=100000, window=3600, burst=1000),
        },
        description="Rate limiting tiers by user type",
    )
    rate_limit_config: Dict[str, Dict[str, Any]] = Field(
        default_factory=lambda: {
            "FREE": {"count": 1, "window": 60},
            "PREMIUM": {"count": 100, "window": 60},
            "ENTERPRISE": {"count": 1000, "window": 60},
        },
        description="Rate limiting configuration by plan",
    )

    # Plan Features Configuration
    plan_features: Dict[str, Dict[str, Any]] = Field(
        default_factory=lambda: {
            "FREE": {
                "smtp_check": False,
                "raw_dns": False,
                "monthly_quota": 500,
                "daily_quota": 1,
                "batch_size": 50,
                "concurrent": 5,
                "priority": "low",
            },
            "PREMIUM": {
                "smtp_check": True,
                "raw_dns": True,
                "monthly_quota": 5000,
                "daily_quota": 100,
                "batch_size": 1000,
                "concurrent": 20,
                "priority": "medium",
            },
            "ENTERPRISE": {
                "smtp_check": True,
                "raw_dns": True,
                "monthly_quota": None,  # Unlimited
                "daily_quota": None,  # Unlimited
                "batch_size": 1000,
                "concurrent": 100,
                "priority": "high",
            },
        },
        description="Feature set for each subscription plan",
    )

    # Nested Configuration Sections
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    validation: EmailValidationSettings = Field(default_factory=EmailValidationSettings)
    dynamic_quotas: DynamicQuotaSettings = Field(default_factory=DynamicQuotaSettings)
    stripe: StripeSettings = Field(default_factory=StripeSettings)
    jwt: JWTSettings = Field(default_factory=JWTSettings)
    documentation: APIDocumentationSettings = Field(default_factory=APIDocumentationSettings)
    monitoring: MonitoringSettings = Field(default_factory=MonitoringSettings)

    # Validators
    @field_validator("rate_limit_config", mode="before")
    @classmethod
    def parse_rate_limit_config(cls, v: Any) -> Dict[str, Dict[str, Any]]:
        """Parse rate limit configuration from JSON string and normalize keys to UPPERCASE"""
        if isinstance(v, str):
            try:
                config = json.loads(v)
                if not isinstance(config, dict):
                    raise ValueError("Rate limit config must be a dictionary")
                return {str(k).upper(): val for k, val in config.items()}
            except (json.JSONDecodeError, ValueError) as e:
                raise ValueError(f"Error parsing rate limit config: {e}")
        return {str(k).upper(): val for k, val in v.items()}

    @field_validator("rate_limits", mode="before")
    @classmethod
    def parse_rate_limits(cls, v: Any) -> Dict[str, RateLimitTier]:
        """Parse rate limits from environment variables"""
        if isinstance(v, str):
            try:
                limits_data = json.loads(v)
                return {tier: RateLimitTier(**config) for tier, config in limits_data.items()}
            except (json.JSONDecodeError, ValueError) as e:
                raise ValueError(f"Error parsing rate limits: {e}")
        return v

    @field_validator("plan_features", mode="before")
    @classmethod
    def parse_plan_features(cls, v: Any) -> Dict[str, Dict[str, Any]]:
        """Parse plan features from environment variables"""
        if isinstance(v, str):
            try:
                features = json.loads(v)
                if not isinstance(features, dict):
                    raise ValueError("Plan features must be a dictionary")
                return {str(k).upper(): val for k, val in features.items()}
            except (json.JSONDecodeError, ValueError) as e:
                raise ValueError(f"Error parsing plan features: {e}")
        return {str(k).upper(): val for k, val in v.items()}

    @field_validator("dynamic_quotas", mode="before")
    @classmethod
    def parse_dynamic_quotas(cls, v: Any) -> DynamicQuotaSettings:
        """Parse dynamic quotas configuration"""
        if isinstance(v, str):
            try:
                data = json.loads(v)
                return DynamicQuotaSettings(**data)
            except (json.JSONDecodeError, ValueError) as e:
                raise ValueError(f"Error parsing dynamic quotas: {e}")
        return v

    @field_validator("environment", mode="before")
    @classmethod
    def validate_environment(cls, v: Any) -> EnvironmentEnum:
        """Validate environment value case-insensitively"""
        if isinstance(v, EnvironmentEnum):
            return v
        if isinstance(v, str):
            v_lower = v.strip().lower()
            try:
                return EnvironmentEnum(v_lower)
            except ValueError:
                allowed = [e.value for e in EnvironmentEnum]
                raise ValueError(f"Environment must be one of {allowed}")
        raise ValueError("Invalid environment type")

    @field_validator("debug", mode="after")
    @classmethod
    def auto_disable_debug_in_production(cls, v: bool, info: Any) -> bool:
        """Automatically disable debug mode in production"""
        environment = info.data.get("environment", EnvironmentEnum.PRODUCTION)
        if environment == EnvironmentEnum.PRODUCTION and v:
            warnings.warn("Debug mode disabled in production environment")
            return False
        return v
    
    @model_validator(mode="after")
    def align_rate_limits_with_plan_features(self) -> "Settings":
        # Si falta rate_limit_config para algún plan, derivar de daily_quota como fallback
        for plan, feats in self.plan_features.items():
            p = str(plan).upper()
            if p not in self.rate_limit_config:
                daily = feats.get("daily_quota")
                # Fallback conservador si None: alto pero no infinito
                derived = {
                    "count": 1000 if daily is None else max(1, int(daily // 24) or 1),
                    "window": 60,
                }
                self.rate_limit_config[p] = derived
        return self

    @model_validator(mode="after")
    def enforce_production_security(self) -> "Settings":
        """Enforce critical security requirements in production"""
        
        # Saltar validaciones si estamos en testing
        if self.testing_mode or os.getenv("TESTING") == "1":
            return self
        
        if self.environment == EnvironmentEnum.PRODUCTION:
            # ✅ NUEVO: Lista de defaults débiles prohibidos
            WEAK_DEFAULTS = {
                "a" * 32,                    # api_key_secret default
                "test_vt_key",               # vt_api_key default
                "test_clearbit_key",         # clearbit_api_key default
                "test_metrics_key",          # metrics_api_key default
                "sk_test_dummy",             # stripe secret_key default
                "pk_test_dummy",             # stripe public_key default
                "whsec_dummy",               # stripe webhook_secret default
                "test_webhook_secret",       # security webhook_secret default
                "test_docs_password",        # docs password default
            }
            
            # HTTPS/HSTS
            if not self.security.https_redirect:
                raise ValueError("https_redirect must be enabled in PRODUCTION")
            if self.security.hsts_max_age <= 0:
                raise ValueError("hsts_max_age must be > 0 in PRODUCTION")
            
            # ✅ JWT secret - validar que no sea default débil
            jwt_secret = self.jwt.secret.get_secret_value()
            if not jwt_secret or len(jwt_secret) < 32:
                raise ValueError("JWT secret must be set and >= 32 chars in PRODUCTION")
            if jwt_secret in WEAK_DEFAULTS:
                raise ValueError("JWT secret cannot use default value in PRODUCTION")
            
            # ✅ Stripe secrets - validar formato y que no sean defaults
            stripe_secret = self.stripe.secret_key.get_secret_value()
            if not stripe_secret or stripe_secret in WEAK_DEFAULTS:
                raise ValueError("Stripe secret_key is required and cannot use default in PRODUCTION")
            if not stripe_secret.startswith(("sk_live_", "sk_test_")):
                raise ValueError("Stripe secret_key must be a valid Stripe key in PRODUCTION")
            
            stripe_public = self.stripe.public_key.get_secret_value()
            if not stripe_public or stripe_public in WEAK_DEFAULTS:
                raise ValueError("Stripe public_key is required and cannot use default in PRODUCTION")
            
            stripe_webhook = self.stripe.webhook_secret.get_secret_value()
            if not stripe_webhook or stripe_webhook in WEAK_DEFAULTS:
                raise ValueError("Stripe webhook_secret is required and cannot use default in PRODUCTION")
            
            # ✅ API key secret - validar que no sea el default débil
            api_key_secret = self.api_key_secret.get_secret_value()
            if not api_key_secret or api_key_secret in WEAK_DEFAULTS:
                raise ValueError(
                    "API_KEY_SECRET is required and cannot use default value in PRODUCTION. "
                    "Generate a strong secret with: python -c 'import secrets; print(secrets.token_hex(32))'"
                )
            if len(api_key_secret) < 32:
                raise ValueError("API_KEY_SECRET must be at least 32 characters in PRODUCTION")
            
            # ✅ VirusTotal API key - debe ser real, no default
            vt_key = self.vt_api_key.get_secret_value()
            if vt_key in WEAK_DEFAULTS:
                raise ValueError("VT_API_KEY cannot use default test value in PRODUCTION")
            
            # ✅ Clearbit API key - debe ser real, no default
            clearbit_key = self.clearbit_api_key.get_secret_value()
            if clearbit_key in WEAK_DEFAULTS:
                raise ValueError("CLEARBIT_API_KEY cannot use default test value in PRODUCTION")
            
            # ✅ Metrics API key - debe ser real, no default
            metrics_key = self.metrics_api_key.get_secret_value()
            if metrics_key in WEAK_DEFAULTS:
                raise ValueError("API_KEY_METRICS cannot use default test value in PRODUCTION")
            
            # SMTP credentials if not localhost
            if self.smtp_host not in {"localhost", "127.0.0.1"}:
                if not self.smtp_username or not self.smtp_password.get_secret_value():
                    raise ValueError(
                        "SMTP credentials are required in PRODUCTION when smtp_host is not localhost"
                    )
        
        return self


    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_nested_delimiter="__",
        case_sensitive=False,
        extra="ignore",
        validate_default=False,
    )


def _rebuild_all_models():
    """Reconstruye todos los modelos Pydantic para resolver forward references"""
    try:
        RateLimitTier.model_rebuild()
        SecuritySettings.model_rebuild()
        EmailValidationSettings.model_rebuild()
        DynamicQuotaSettings.model_rebuild()
        StripeSettings.model_rebuild()
        JWTSettings.model_rebuild()
        APIDocumentationSettings.model_rebuild()
        MonitoringSettings.model_rebuild()
        Settings.model_rebuild()
    except Exception as e:
        # Log warning but don't crash on rebuild (circular imports sometimes cause this)
        warnings.warn(f"Model rebuild failed: {e}")

_rebuild_all_models()


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Get application settings with caching for performance.
    """
    # Testing environment override
    if os.getenv("TESTING") == "1":
        return Settings(
            environment=EnvironmentEnum.TESTING,
            testing_mode=True,
            debug=True,
            security=SecuritySettings(
                cors_origins=["http://localhost:5173", "http://localhost:8000"],
                https_redirect=False,
                hsts_max_age=0,
                webhook_secret=SecretStr("test_webhook_secret"),
            ),
            redis_url=RedisDsn("redis://localhost:6379/0"),
            stripe=StripeSettings(
                secret_key=SecretStr("sk_test_0000000000000000000000000000000000000000000"),
                public_key=SecretStr("pk_test_0000000000000000000000000000000000000000000"),
                webhook_secret=SecretStr("whsec_0000000000000000000000000000000000000000000"),
                premium_plan_id="price_test_premium",
                enterprise_plan_id="price_test_enterprise",
            ),
            jwt=JWTSettings(
                secret=SecretStr("test_jwt_secret_that_is_long_enough_for_validation"),
                issuer="test-issuer",
                audience="test-audience",
            ),
            api_key_secret=SecretStr("test_api_secret_that_is_also_long_enough"),
            vt_api_key=SecretStr("test_vt_key"),
            clearbit_api_key=SecretStr("test_clearbit_key"),
            metrics_api_key=SecretStr("test_metrics_api_key"),
            enable_test_routes=True,
        )

    # Development environment defaults (case-insensitive)
    env_raw = os.getenv("ENVIRONMENT", "").strip().lower()
    if env_raw == "development":
        return Settings(
            environment=EnvironmentEnum.DEVELOPMENT,
            debug=True,
            enable_test_routes=True,
        )

    # Production - load from environment with full validation
    return Settings()


# Global settings instance
settings = get_settings()


def display_config_summary() -> None:
    """Display sanitized configuration summary for debugging"""
    print("\n" + "=" * 50)
    print("CONFIGURATION SUMMARY")
    print("=" * 50)
    print(f"Environment: {settings.environment.value}")
    print(f"Debug Mode: {settings.debug}")
    print(f"Testing Mode: {settings.testing_mode}")
    print(f"Redis URL: {settings.redis_url}")
    print(f"Frontend URL: {settings.frontend_url}")
    print(f"CORS Origins: {settings.security.cors_origins}")
    print(f"Stripe Enabled: {bool(settings.stripe.secret_key.get_secret_value())}")
    print(f"Documentation: {settings.documentation.enabled}")
    print(f"Monitoring: {settings.monitoring.sentry_dsn is not None}")
    print("=" * 50 + "\n")


if __name__ == "__main__":
    # Configuration validation and display
    display_config_summary()

    # Stripe configuration check (sanitized)
    stripe_key = settings.stripe.secret_key.get_secret_value()
    print("Stripe Configuration:")
    print(f" Key Present: {'Yes' if stripe_key else 'No'}")
    print(f" Key Type: {'Live' if stripe_key.startswith('sk_live_') else 'Test' if stripe_key else 'None'}")
    print(f" Premium Plan: {settings.stripe.premium_plan_id}")
    print(f" Enterprise Plan: {settings.stripe.enterprise_plan_id}")

    # Rate limiting overview
    print(f"\nRate Limits:")
    for plan, limits in settings.rate_limit_config.items():
        print(f" {plan}: {limits['count']} req/{limits['window']}s")
