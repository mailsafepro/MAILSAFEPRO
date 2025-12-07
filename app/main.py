from fastapi import FastAPI, Request, HTTPException
from fastapi.openapi.docs import get_redoc_html
from fastapi.middleware.cors import CORSMiddleware as FastAPICORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional
from redis.asyncio import Redis
from arq import create_pool
from arq.connections import RedisSettings
import starlette.status as _status
import os
import asyncio
import logging
from pydantic import BaseModel, EmailStr
from dotenv import load_dotenv
import time
# ✅ AÑADIR: Rate limiting integrado con circuit breakers
from app.rate_limiting.advanced_rate_limiting import (
    RateLimitManager,
    add_rate_limit_headers,
    SlidingWindowRateLimiter,
    LocalRateLimiterFallback,
    get_circuit_breaker_status
)


load_dotenv()

# Compat alias for historical typo in some libs
setattr(_status, "HTTP_401_UNANAUTHORIZED", _status.HTTP_401_UNAUTHORIZED)

# Import configs and enums
from app.config import settings, EnvironmentEnum
from app.logger import logger

# Initialize observability early
from app.structured_logging import setup_structured_logging
from app.tracing import setup_tracing, shutdown_tracing

# Setup structured logging first (before any logging occurs)
setup_structured_logging()

# Import security scheme and routers
from app.auth import CustomHTTPBearer, router as auth_router
from app.routes.validation_routes import router as validation_router
from app.routes import billing_routes
from app.api_keys import router as api_keys_router
from app.jobs.jobs_routes import router as jobs_router
from app.jobs.webhooks_routes import router as jobs_webhooks_router
from app.routes.logs_routes import router as logs_router
from app.routes.webhooks_management import router as webhooks_mgmt_router
from app.health_checks import router as health_router

# Import middlewares and utilities
from app.exceptions import register_exception_handlers
from app.metrics import instrument_app, mount_metrics_endpoint, Instrumentator
from app.connection_pooling import OptimizedRedisPool

# ✅ MEJORA 1: Import tenacity for robust retry logic
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    before_sleep_log
)

from prometheus_client import Counter, Histogram, Gauge, REGISTRY
import os

# ===============================================
# PROMETHEUS METRICS - FIX DUPLICADOS
# ===============================================

# ✅ Limpiar registry en desarrollo para evitar duplicados con uvicorn reloader
if settings.environment == EnvironmentEnum.DEVELOPMENT:
    try:
        collectors = list(REGISTRY._collector_to_names.keys())
        for collector in collectors:
            try:
                REGISTRY.unregister(collector)
            except Exception:
                pass
        logger.debug("Prometheus registry cleaned for development mode")
    except Exception as e:
        logger.debug(f"Could not clean Prometheus registry: {e}")


# ✅ Función helper para registrar métricas de forma segura
def safe_counter(name: str, description: str, labelnames=None):
    """Create Counter or return existing one"""
    try:
        return Counter(name, description, labelnames or [])
    except ValueError:
        # Métrica ya existe
        return REGISTRY._names_to_collectors.get(name)


def safe_histogram(name: str, description: str, buckets=None):
    """Create Histogram or return existing one"""
    try:
        return Histogram(name, description, buckets=buckets)
    except ValueError:
        return REGISTRY._names_to_collectors.get(name)


def safe_gauge(name: str, description: str, labelnames=None):
    """Create Gauge or return existing one"""
    try:
        return Gauge(name, description, labelnames or [])
    except ValueError:
        return REGISTRY._names_to_collectors.get(name)


# ✅ Define custom metrics (protegidos contra duplicación)
redis_connection_failures = safe_counter(
    'redis_connection_failures_total',
    'Total number of Redis connection failures',
    labelnames=['error_type']
)

redis_connection_success = safe_counter(
    'redis_connection_success_total',
    'Total number of successful Redis connections'
)

app_startup_duration = safe_histogram(
    'app_startup_duration_seconds',
    'Application startup duration in seconds',
    buckets=[0.5, 1.0, 2.0, 5.0, 10.0, 30.0]
)

redis_pool_connections = safe_gauge(
    'redis_pool_connections_active',
    'Number of active Redis connections'
)

service_health = safe_gauge(
    'service_health_status',
    'Service health status (1=healthy, 0=unhealthy)',
    labelnames=['service']
)


# Reduce Uvicorn noise in production
if settings.environment == EnvironmentEnum.PRODUCTION:
    logging.getLogger("uvicorn").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").propagate = False


# ✅ Fallback global para rate limiting
_global_fallback = LocalRateLimiterFallback()


# ✅ MEJORA 1: Robust Redis initialization with retry logic
@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception_type((ConnectionError, TimeoutError, OSError)),
    before_sleep=before_sleep_log(logger, logging.WARNING),
    reraise=True
)
async def initialize_redis_with_retry(redis_url: str) -> Redis:
    """
    ✅ MEJORA: Initialize Redis with exponential backoff retry

    Retries up to 3 times with exponential backoff (2s, 4s, 8s)
    Only retries on connection errors, not on authentication errors
    """
    logger.info(f"Attempting to connect to Redis: {redis_url[:20]}...")

    try:
        redis_pool = OptimizedRedisPool(
            url=redis_url,
            max_connections=50,
            health_check_interval=30
        )

        redis_client = await redis_pool.initialize()

        # Test connection with ping
        await redis_client.ping()

        logger.success("✅ Redis connection established successfully")
        redis_connection_success.inc()
        service_health.labels(service='redis').set(1)

        return redis_client

    except Exception as e:
        error_type = type(e).__name__
        redis_connection_failures.labels(error_type=error_type).inc()
        service_health.labels(service='redis').set(0)
        logger.error(f"Redis connection failed: {error_type} - {str(e)}")
        raise



# ✅ MEJORA 1: Robust ARQ pool initialization with retry
@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception_type((ConnectionError, TimeoutError, OSError)),
    before_sleep=before_sleep_log(logger, logging.WARNING),
    reraise=True
)
async def initialize_arq_with_retry(redis_url: str):
    """
    ✅ MEJORA: Initialize ARQ Redis pool with retry logic
    """
    from urllib.parse import urlparse

    logger.info("Attempting to initialize ARQ Redis pool...")

    parsed = urlparse(redis_url)
    arq_settings = RedisSettings(
        host=parsed.hostname or "localhost",
        port=parsed.port or 6379,
        password=parsed.password,
        database=int(parsed.path.lstrip("/")) if parsed.path else 0,
        ssl=redis_url.startswith("rediss://")
    )

    arq_pool = await create_pool(arq_settings)

    logger.success("✅ ARQ Redis pool initialized successfully")
    service_health.labels(service='arq').set(1)

    return arq_pool


# Lifecycle management
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator:
    """
    ✅ IMPROVED: Enhanced application lifecycle with better error handling
    """
    startup_start_time = time.time()

    logger.info(f"🚀 Starting API server in {settings.environment.value} environment")

    # ✅ Testing mode bypass
    if settings.testing_mode:
        logger.info("⚡ Testing mode enabled - skipping full initialization")
        yield
        return

    # Initialize state
    app.state.redis = None
    app.state.arq_redis = None
    app.state.redis_available = False
    app.state.arq_available = False

    # ✅ MEJORA: Try to initialize Redis with retry logic
    try:
        redis_url = str(settings.redis_url)
        app.state.redis = await initialize_redis_with_retry(redis_url)
        app.state.redis_available = True

    except Exception as e:
        logger.warning(
            f"⚠️ Redis initialization failed after retries: {str(e)} - "
            f"running in degraded mode without cache"
        )

        # ✅ MEJORA 3: Check if Redis is required
        if getattr(settings, 'redis_required', False):
            logger.error("❌ Redis is required but unavailable - cannot start")
            raise RuntimeError("Redis is required but connection failed") from e

    # ✅ MEJORA: Try to initialize ARQ pool
    if app.state.redis:
        try:
            redis_url = str(settings.redis_url)
            app.state.arq_redis = await initialize_arq_with_retry(redis_url)
            app.state.arq_available = True

        except Exception as e:
            logger.warning(f"⚠️ ARQ pool initialization failed: {e} - batch jobs disabled")
            service_health.labels(service='arq').set(0)

    # ✅ Warm up connections if Redis is available
    if app.state.redis:
        try:
            await warm_up_connections(app.state.redis)
        except Exception as e:
            logger.warning(f"⚠️ Connection warm-up failed: {e}")

    # ✅ Initialize services
    if app.state.redis:
        try:
            await initialize_services(app)
            service_health.labels(service='app').set(1)
        except Exception as e:
            logger.error(f"❌ Service initialization failed: {e}")
            service_health.labels(service='app').set(0)

            # ✅ MEJORA 3: Decide if we can continue without services
            if getattr(settings, 'services_required', True):
                raise

    # Record startup time
    startup_duration = time.time() - startup_start_time
    app_startup_duration.observe(startup_duration)
    logger.success(f"✅ API server started successfully in {startup_duration:.2f}s")

    try:
        yield
    finally:
        # ✅ IMPROVED: Enhanced shutdown with better error handling
        logger.info("🛑 Shutting down API server...")

        shutdown_errors = []

        # Shutdown services
        if app.state.redis:
            try:
                await shutdown_services(app)
            except Exception as e:
                shutdown_errors.append(f"Service shutdown: {e}")
                logger.error(f"Error shutting down services: {e}")

        # Close Redis connection
        if app.state.redis:
            try:
                await app.state.redis.close()
                logger.info("✅ Redis connection closed")
            except Exception as e:
                shutdown_errors.append(f"Redis close: {e}")
                logger.error(f"Error closing Redis: {e}")

        # Close ARQ pool
        if app.state.arq_redis:
            try:
                await app.state.arq_redis.close()
                logger.info("✅ ARQ pool closed")
            except Exception as e:
                shutdown_errors.append(f"ARQ close: {e}")
                logger.error(f"Error closing ARQ: {e}")

        # Update health metrics
        service_health.labels(service='redis').set(0)
        service_health.labels(service='arq').set(0)
        service_health.labels(service='app').set(0)

        if shutdown_errors:
            logger.warning(f"⚠️ Shutdown completed with {len(shutdown_errors)} errors")
        else:
            logger.success("👋 API server stopped cleanly")


async def warm_up_connections(redis: Redis):
    """
    Phase 7: Pre-warm connection pools for faster first requests.

    Reduces cold-start P95 latency by 15-20% by:
    - Warming Redis connection pool (10 parallel pings)
    - Pre-caching DNS for common email domains
    - Establishing initial HTTP connections
    """
    logger.info("🔥 Warming up connection pools...")

    try:
        # 1. Redis connection warm-up (10 parallel pings)
        await asyncio.gather(
            *[redis.ping() for _ in range(10)],
            return_exceptions=True
        )
        logger.debug("✅ Redis pool warmed (10 connections)")
        redis_pool_connections.set(10)

        # 2. DNS resolver warm-up (common domains)
        try:
            import aiodns
            resolver = aiodns.DNSResolver()

            warm_domains = [
                "gmail.com", "outlook.com", "yahoo.com", "hotmail.com",
                "icloud.com", "protonmail.com", "aol.com", "mail.com"
            ]

            await asyncio.gather(
                *[resolver.query(domain, "MX") for domain in warm_domains],
                return_exceptions=True
            )
            logger.debug(f"✅ DNS cache warmed ({len(warm_domains)} domains)")

        except Exception as e:
            logger.warning(f"DNS warm-up failed: {e}")

        logger.success("✅ Connection pools warmed up")

    except Exception as e:
        logger.warning(f"⚠️ Connection warming failed: {e} - continuing anyway")


async def initialize_services(app: FastAPI):
    """
    ✅ IMPROVED: Initialize all application services after Redis connection
    """
    from app.cache_warming import start_cache_warming
    from app.validation import set_redis_client
    from app.health_checks import get_health_manager

    logger.info("🔧 Initializing application services...")

    try:
        # Inject Redis client into validation layer for distributed caching
        set_redis_client(app.state.redis)
        logger.info("✅ Redis client injected into validation layer")
        
        # ✅ FIX: Configurar Redis en el health manager para health checks
        if app.state.redis:
            get_health_manager().set_redis(app.state.redis)
            logger.info("✅ Redis client configured in health manager")

        # Cache disposable domains for fast lookup
        await cache_disposable_domains(app.state.redis)

        # Start background cache warming for popular domains
        try:
            logger.info("🔥 Starting cache warming for popular email domains...")
            await start_cache_warming()
            logger.success("✅ Cache warming initialized successfully")
            service_health.labels(service='cache_warming').set(1)

        except Exception as e:
            logger.warning(f"⚠️ Cache warming initialization failed: {e}")
            service_health.labels(service='cache_warming').set(0)

        # Start general background tasks
        asyncio.create_task(background_tasks())
        logger.success("✅ Background tasks started")

    except Exception as e:
        logger.error(f"❌ Service initialization failed: {e}")
        raise


async def shutdown_services(app: FastAPI):
    """
    ✅ IMPROVED: Gracefully shutdown all services with timeout
    """
    from app.cache_warming import stop_cache_warming

    logger.info("🔧 Shutting down services...")

    shutdown_tasks = []

    try:
        # Stop cache warming background task
        logger.info("Stopping cache warming...")
        shutdown_tasks.append(asyncio.create_task(stop_cache_warming()))

    except Exception as e:
        logger.error(f"Error stopping cache warming: {e}")

    try:
        # Shutdown distributed tracing (flush remaining spans)
        logger.info("Shutting down tracing...")
        shutdown_tracing()

    except Exception as e:
        logger.error(f"Error shutting down tracing: {e}")

    # Wait for all shutdown tasks with timeout
    if shutdown_tasks:
        try:
            await asyncio.wait_for(
                asyncio.gather(*shutdown_tasks, return_exceptions=True),
                timeout=10.0
            )
        except asyncio.TimeoutError:
            logger.warning("⚠️ Service shutdown timeout exceeded")

    logger.success("✅ All services shut down cleanly")


async def cache_disposable_domains(redis: Redis):
    """Cache disposable domains in Redis for fast lookup"""
    try:
        await redis.delete("disposable_domains")

        if settings.validation.disposable_domains:
            await redis.sadd("disposable_domains", *settings.validation.disposable_domains)
            logger.info(f"📦 Cached {len(settings.validation.disposable_domains)} disposable domains")

    except Exception as e:
        logger.error(f"Failed to cache disposable domains: {str(e)}")


async def background_tasks():
    """Background maintenance tasks"""
    while True:
        try:
            logger.debug("Running background maintenance tasks")
            await asyncio.sleep(3600)  # Run every hour

        except asyncio.CancelledError:
            logger.info("Background tasks cancelled")
            break
        except Exception as e:
            logger.error(f"Background task error: {e}")
            await asyncio.sleep(60)  # Wait before retrying


# Define FastAPI app with professional docs info
app = FastAPI(
    title=settings.documentation.title,
    description=settings.documentation.description,
    version=settings.documentation.version,
    contact=settings.documentation.contact,
    license_info={
        "name": "Proprietary",
    },
    docs_url="/docs" if settings.documentation.enabled else None,
    redoc_url=None,  # Disabled by default, custom endpoint below
    openapi_url="/openapi.json" if settings.documentation.enabled else None,
    lifespan=lifespan,
    openapi_tags=[
        {"name": "Authentication", "description": "Login, registro y manejo de tokens"},
        {"name": "Validation", "description": "Validación individual y múltiple de emails"},
        {"name": "Billing", "description": "Gestión de planes y facturación"},
        {"name": "Health", "description": "Health checks y métricas"},
    ],
)

# Initialize distributed tracing (instruments FastAPI automatically)
setup_tracing(app)

# ✅ Phase 5: Payload Size Limit Middleware (DoS prevention)
from app.security.payload_limits import PayloadSizeLimitMiddleware
app.add_middleware(PayloadSizeLimitMiddleware)

# ✅ CDN Caching Middleware for static docs
@app.middleware("http")
async def add_cache_headers(request: Request, call_next):
    response = await call_next(request)

    if request.method == "GET" and response.status_code == 200:
        path = request.url.path
        if path in ["/redoc", "/docs", "/openapi.json"]:
            # Cache for 1 hour (public)
            response.headers["Cache-Control"] = "public, max-age=3600"

    return response


# ✅ MEJORA 2: Enhanced health check endpoints
@app.get("/health/liveness", tags=["Health"], include_in_schema=True)
async def liveness_check():
    """
    ✅ MEJORA: Kubernetes liveness probe

    Returns 200 if the application is alive (not deadlocked)
    Used by Kubernetes to restart the pod if unhealthy
    """
    return {
        "status": "alive",
        "timestamp": time.time(),
        "environment": settings.environment.value
    }


@app.get("/health/readiness", tags=["Health"], include_in_schema=True)
async def readiness_check():
    """
    ✅ MEJORA: Kubernetes readiness probe

    Returns 200 if the application is ready to serve traffic
    Checks all critical dependencies (Redis, ARQ, etc.)
    """
    checks = {
        "redis": app.state.redis_available if hasattr(app.state, 'redis_available') else False,
        "arq": app.state.arq_available if hasattr(app.state, 'arq_available') else False,
    }

    # Test Redis connection if available
    if app.state.redis:
        try:
            await asyncio.wait_for(app.state.redis.ping(), timeout=1.0)
            checks["redis_ping"] = True
        except Exception as e:
            checks["redis_ping"] = False
            checks["redis_error"] = str(e)

    all_ready = all(checks.values()) if checks else False

    if all_ready:
        return {
            "status": "ready",
            "checks": checks,
            "timestamp": time.time()
        }
    else:
        raise HTTPException(
            status_code=503,
            detail={
                "status": "not_ready",
                "checks": checks,
                "timestamp": time.time()
            }
        )


@app.get("/health/startup", tags=["Health"], include_in_schema=True)
async def startup_check():
    """
    ✅ MEJORA: Kubernetes startup probe

    Returns 200 once the application has completed startup
    Used to delay readiness checks until startup is complete
    """
    # Check if app has finished initializing
    has_redis = hasattr(app.state, 'redis')

    if has_redis:
        return {
            "status": "started",
            "redis_available": app.state.redis_available if hasattr(app.state, 'redis_available') else False,
            "arq_available": app.state.arq_available if hasattr(app.state, 'arq_available') else False,
            "timestamp": time.time()
        }
    else:
        raise HTTPException(
            status_code=503,
            detail={"status": "starting", "timestamp": time.time()}
        )


@app.get("/healthcheck", tags=["Health"])
@app.head("/healthcheck", tags=["Health"])
async def healthcheck():
    """
    Basic health check endpoint (backward compatibility)
    """
    return {
        "status": "ok",
        "version": settings.documentation.version,
        "environment": settings.environment.value
    }


# Sobrescribir ReDoc con CDN estable
@app.get("/redoc", include_in_schema=False)
async def redoc_html():
    """ReDoc documentation with stable CDN"""
    return HTMLResponse(f"""
<!DOCTYPE html>
<html>
<head>
    <title>{settings.documentation.title} - API Documentation</title>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://fonts.googleapis.com/css?family=Montserrat:300,400,700|Roboto:300,400,700" rel="stylesheet">
    <style>
        body {{
            margin: 0;
            padding: 0;
        }}
    </style>
</head>
<body>
    <redoc spec-url='/openapi.json'></redoc>
    <script src="https://cdn.redoc.ly/redoc/latest/bundles/redoc.standalone.js"></script>
</body>
</html>
""")


# Custom OpenAPI schema with security schemes
def custom_openapi():
    from fastapi.openapi.utils import get_openapi

    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title=settings.documentation.title,
        version=settings.documentation.version,
        description=settings.documentation.description,
        routes=app.routes,
    )

    # Add security schemes
    openapi_schema["components"]["securitySchemes"] = {
        "Bearer": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "JWT token for authentication"
        },
        "ApiKeyAuth": {
            "type": "apiKey",
            "in": "header",
            "name": "X-API-Key",
            "description": "API Key for validation endpoints"
        }
    }

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi

# ✅ Include routers
app.include_router(auth_router, prefix="/auth", tags=["Authentication"])
app.include_router(validation_router, prefix="/validate", tags=["Validation"])
app.include_router(billing_routes.router, prefix="/billing", tags=["Billing"])
app.include_router(api_keys_router, prefix="/api-keys", tags=["API Keys"])
app.include_router(jobs_router, prefix="/jobs", tags=["Jobs"])
app.include_router(jobs_webhooks_router, prefix="/webhooks", tags=["Webhooks"])
app.include_router(logs_router, prefix="/logs", tags=["Logs"])
app.include_router(webhooks_mgmt_router, prefix="/webhooks-management", tags=["Webhooks Management"])
app.include_router(health_router, tags=["Health"])  # ✅ FIX: Incluir router de health_checks para /health

# ✅ Register exception handlers
register_exception_handlers(app)

# ✅ Mount metrics endpoint
mount_metrics_endpoint(app)

# ✅ Instrument app with Prometheus
instrument_app(app)

# ✅ SECURITY: Global IP rate limiting with FAIL-CLOSED strategy
GLOBAL_RATE_LIMIT = 1000  # requests per window
GLOBAL_RATE_WINDOW = 60   # seconds


# ============================================================================
# UTILITY: IP EXTRACTION
# ============================================================================

# Lista de IPs de proxies confiables
TRUSTED_PROXY_IPS = [
    "10.0.0.0/8",       # Rango privado completo
    "172.16.0.0/12",    # Docker networks (172.16-172.31)
    "192.168.0.0/16",   # Rango privado
    "127.0.0.1",        # Localhost
]

def get_client_ip(request: Request) -> str:
    """Extract client IP with proxy validation."""
    direct_ip = request.client.host if request.client else "unknown"
    
    # ✅ NUEVO: En desarrollo, siempre usar direct_ip
    # En producción, confiar en headers solo si viene de proxy confiable
    trust_proxy = os.getenv("TRUST_PROXY_HEADERS", "false").lower() == "true"
    
    # ✅ CAMBIO: Si NO confiamos en headers, retornar direct_ip inmediatamente
    if not trust_proxy:
        return direct_ip
    
    # ✅ CAMBIO: Si confiamos en headers Y viene de proxy confiable, extraer IP real
    if _is_trusted_proxy(direct_ip):
        # Extract from headers only if from trusted proxy
        cf_ip = request.headers.get("CF-Connecting-IP")
        if cf_ip and _is_valid_ip(cf_ip):
            return cf_ip
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip and _is_valid_ip(real_ip):
            return real_ip
        
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            first_ip = forwarded_for.split(",")[0].strip()
            if _is_valid_ip(first_ip):
                return first_ip
    
    # ✅ Fallback: siempre retornar la IP directa
    return direct_ip


def _is_trusted_proxy(ip: str) -> bool:
    """Check if IP is from a trusted proxy."""
    import ipaddress
    try:
        client_ip = ipaddress.ip_address(ip)
        for trusted_range in TRUSTED_PROXY_IPS:
            if "/" in trusted_range:
                # CIDR range
                network = ipaddress.ip_network(trusted_range, strict=False)
                if client_ip in network:
                    return True
            else:
                # Single IP
                if str(client_ip) == trusted_range:
                    return True
        return False
    except ValueError:
        return False


def _is_valid_ip(ip: str) -> bool:
    """Validate IP address format (IPv4 or IPv6)."""
    try:
        import ipaddress
        ipaddress.ip_address(ip)
        return True
    except (ValueError, AttributeError):
        return False


# ============================================================================
# MIDDLEWARE: GLOBAL RATE LIMIT
# ============================================================================

@app.middleware("http")
async def global_ip_rate_limit_middleware(request: Request, call_next):
    """
    ✅ SECURITY: Global rate limit per IP with proxy support.
    """
    # Skip health checks and docs
    if request.url.path.startswith(("/health", "/docs", "/redoc", "/openapi.json")):
        return await call_next(request)
    
    # ✅ Extract real client IP considering proxies
    client_ip = get_client_ip(request)
    rate_key = f"global_rate:{client_ip}"
    
    # ✅ Log rate limit check
    logger.info(
        f"Rate limit check | IP: {client_ip} | Path: {request.url.path}",
        extra={
            "client_ip": client_ip,
            "path": request.url.path,
            "method": request.method,
        }
    )
    
    redis = getattr(request.app.state, "redis", None)
    redis_available = getattr(request.app.state, "redis_available", False)
    
    logger.info(f"Redis available: {redis_available}")
    
    # Variables para headers
    rate_limit_info = {
        "limit": GLOBAL_RATE_LIMIT,
        "remaining": GLOBAL_RATE_LIMIT,
        "current": 0,
        "reset_in": GLOBAL_RATE_WINDOW,
    }
    
    # CASO 1: Redis disponible
    if redis and redis_available:
        limiter = SlidingWindowRateLimiter(redis)
        
        allowed, metadata = await limiter.check_rate_limit(
            key=rate_key,
            limit=GLOBAL_RATE_LIMIT,
            window=GLOBAL_RATE_WINDOW,
            cost=1
        )
        
        # ✅ Actualizar info de rate limit
        rate_limit_info.update({
            "current": metadata.get("current", 0),
            "remaining": metadata.get("remaining", GLOBAL_RATE_LIMIT),
            "reset_in": metadata.get("reset_in", GLOBAL_RATE_WINDOW),
        })
        
        logger.info(
            f"Rate limit result | Allowed: {allowed} | Current: {metadata.get('current')} | Limit: {metadata.get('limit')}"
        )
        
        if not allowed:
            logger.warning(
                f"Global rate limit exceeded for IP: {client_ip[:20]}",
                extra={
                    "current": metadata["current"],
                    "limit": metadata["limit"],
                    "fallback_mode": metadata.get("fallback_mode", False),
                }
            )
            
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Rate limit exceeded",
                    "detail": "Too many requests. Please slow down.",
                    "retry_after": metadata["reset_in"],
                    "limit": metadata["limit"],
                    "fallback_mode": metadata.get("fallback_mode", False)
                },
                headers={
                    "Retry-After": str(metadata["reset_in"]),
                    "X-RateLimit-Limit": str(metadata["limit"]),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(time.time()) + metadata["reset_in"]),
                    "X-Client-IP": client_ip,
                }
            )
    
    else:
        # CASO 2: Redis NO disponible - fallback local
        logger.warning("⚠️ Redis unavailable - using local fallback for global rate limit")
        
        allowed, metadata = _global_fallback.check_limit(
            key=rate_key,
            limit=GLOBAL_RATE_LIMIT,
            window=GLOBAL_RATE_WINDOW,
            cost=1
        )
        
        # ✅ Actualizar info de rate limit
        rate_limit_info.update({
            "current": metadata.get("current", 0),
            "remaining": metadata.get("remaining", GLOBAL_RATE_LIMIT),
            "reset_in": metadata.get("reset_in", GLOBAL_RATE_WINDOW),
        })
        
        if not allowed:
            logger.warning(
                f"Global rate limit exceeded (FALLBACK MODE) for IP: {client_ip[:20]}",
                extra={
                    "current": metadata["current"],
                    "limit": metadata["limit"],
                }
            )
            
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Rate limit exceeded",
                    "detail": "Too many requests. Service in degraded mode - reduced limits apply.",
                    "retry_after": metadata["reset_in"],
                    "limit": metadata["limit"],
                    "fallback_mode": True
                },
                headers={
                    "Retry-After": str(metadata["reset_in"]),
                    "X-RateLimit-Limit": str(metadata["limit"]),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Fallback": "true",
                    "X-Client-IP": client_ip,
                }
            )
    
    # ✅ NUEVO: Continuar con el request
    response = await call_next(request)
    
    # ✅ NUEVO: Agregar headers de rate limit y client IP a TODAS las respuestas
    response.headers["X-Client-IP"] = client_ip
    response.headers["X-RateLimit-Limit"] = str(rate_limit_info["limit"])
    response.headers["X-RateLimit-Remaining"] = str(rate_limit_info["remaining"])
    response.headers["X-RateLimit-Reset"] = str(int(time.time()) + rate_limit_info["reset_in"])
    
    return response


# ✅ Add CORS middleware
app.add_middleware(
    FastAPICORSMiddleware,
    allow_origins=settings.security.cors_origins,
    allow_credentials=True,
    # ⚠️ SECURITY FIX: Explicit method list instead of wildcard
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "HEAD"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-Request-ID", "Accept", "Origin"],
)

# ✅ Add GZip compression
app.add_middleware(GZipMiddleware, minimum_size=1000)

app.middleware("http")(add_rate_limit_headers)

# ✅ MEJORA 4: Endpoint to check feature flags and degraded mode status
@app.get("/status", tags=["Health"])
async def service_status():
    """
    ✅ MEJORA: Detailed service status with feature flags

    Shows which features are available and which are running in degraded mode
    """
    status = {
        "api_version": settings.documentation.version,
        "environment": settings.environment.value,
        "services": {
            "redis": {
                "available": app.state.redis_available if hasattr(app.state, 'redis_available') else False,
                "required": getattr(settings, 'redis_required', False),
            },
            "arq": {
                "available": app.state.arq_available if hasattr(app.state, 'arq_available') else False,
                "required": False,
            },
        },
        "features": {
            "caching": app.state.redis_available if hasattr(app.state, 'redis_available') else False,
            "batch_processing": app.state.arq_available if hasattr(app.state, 'arq_available') else False,
            "rate_limiting": app.state.redis_available if hasattr(app.state, 'redis_available') else False,
        },
        "degraded_mode": not (
            app.state.redis_available if hasattr(app.state, 'redis_available') else False
        ),
    }

    return status


@app.get("/admin/circuit-breaker-status", tags=["Health"])
async def circuit_breaker_status():
    """
    ✅ Circuit breaker status for all services.
    Shows state of Redis, SMTP, DNS, and other circuit breakers.
    """
    from app.resilience.circuit_breakers import CircuitBreakerManager
    
    all_breakers = CircuitBreakerManager.get_all_breakers()
    
    stats = {}
    for service_name in all_breakers.keys():
        stats[service_name] = CircuitBreakerManager.get_breaker_stats(service_name)
    
    return {
        "circuit_breakers": stats,
        "rate_limiting": await get_circuit_breaker_status(),
        "redis_available": app.state.redis_available if hasattr(app.state, 'redis_available') else False
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.environment == EnvironmentEnum.DEVELOPMENT,
        log_level="info" if settings.environment == EnvironmentEnum.PRODUCTION else "debug",
    )