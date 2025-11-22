from fastapi import FastAPI, Request, Body
from fastapi.openapi.docs import get_redoc_html
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
from contextlib import asynccontextmanager
from redis.asyncio import Redis
import starlette.status as _status
import os
import asyncio
import logging
from pydantic import BaseModel, EmailStr
from dotenv import load_dotenv
load_dotenv()

# Compat alias for historical typo in some libs
setattr(_status, "HTTP_401_UNANAUTHORIZED", _status.HTTP_401_UNAUTHORIZED)

# Import configs and enums
from app.config import settings, EnvironmentEnum
from app.logger import logger

# Import security scheme and routers
from app.auth import CustomHTTPBearer, router as auth_router
from app.routes.validation_routes import router as validation_router
from app.routes import protected_test as test_routes, billing_routes
from app.api_keys import router as api_keys_router
from app.jobs.jobs_routes import router as jobs_router
from app.jobs.webhooks_routes import router as jobs_webhooks_router

# Import middlewares
from app.middleware import (
    SecurityHeadersMiddleware, RateLimitMiddleware, HistoricalKeyMiddleware,
    LoggingMiddleware, MetricsMiddleware
)

# Import exceptions and metrics utilities
from app.exceptions import register_exception_handlers
from app.metrics import instrument_app, mount_metrics_endpoint, Instrumentator, metrics_middleware

# Reduce Uvicorn noise in production
if settings.environment == EnvironmentEnum.PRODUCTION:
    logging.getLogger("uvicorn").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").propagate = False

# Lifecycle management
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"🚀 Starting API server in {settings.environment.value} environment")

    if settings.testing_mode:
        yield
        return

    # Redis connection con soporte SSL
    app.state.redis = None
    
    try:
        redis_url = str(settings.redis_url)
        logger.info(f"Attempting to connect to Redis...")
        
        # Configurar SSL si la URL usa rediss://
        connection_kwargs = {
            "decode_responses": True,
            "socket_timeout": 10,
            "socket_connect_timeout": 10,
            "socket_keepalive": True,
            "retry_on_timeout": True,
            "health_check_interval": 30
        }
        
        # Si usa rediss:// (SSL), añadir configuración SSL
        if redis_url.startswith("rediss://"):
            import ssl
            connection_kwargs["ssl_cert_reqs"] = ssl.CERT_NONE  # Desactiva validación de certificado
            logger.info("Using SSL connection for Redis")
        
        redis_client = Redis.from_url(redis_url, **connection_kwargs)
        
        # Intentar conectar con reintentos
        max_retries = 5
        retry_delay = 3
        
        for attempt in range(1, max_retries + 1):
            try:
                logger.info(f"Redis connection attempt {attempt}/{max_retries}...")
                await asyncio.wait_for(redis_client.ping(), timeout=10)
                app.state.redis = redis_client
                logger.success(f"✅ Redis connection successful on attempt {attempt}")
                await initialize_services(app)
                break
            except asyncio.TimeoutError:
                if attempt < max_retries:
                    logger.warning(f"Redis timeout on attempt {attempt}, retrying in {retry_delay}s...")
                    await asyncio.sleep(retry_delay)
                else:
                    logger.error("⚠️ Redis connection timeout - running without cache")
            except Exception as e:
                if attempt < max_retries:
                    logger.warning(f"Redis error on attempt {attempt}: {str(e)}, retrying...")
                    await asyncio.sleep(retry_delay)
                else:
                    logger.error(f"⚠️ Redis connection failed: {str(e)} - running without cache")
        
    except Exception as e:
        logger.warning(f"⚠️ Redis initialization failed: {str(e)} - running without cache")

    try:
        yield
    finally:
        logger.info("🛑 Shutting down API server...")
        if app.state.redis:
            try:
                await shutdown_services(app)
                await app.state.redis.close()
            except Exception:
                pass
        logger.success("👋 API server stopped cleanly")


async def initialize_services(app: FastAPI):
    from app.smtp import smtp_breaker
    smtp_breaker.close()
    await cache_disposable_domains(app.state.redis)
    asyncio.create_task(background_tasks())

async def shutdown_services(app: FastAPI):
    try:
        await app.state.redis.close()
    except Exception:
        pass

async def cache_disposable_domains(redis: Redis):
    try:
        await redis.delete("disposable_domains")
        if settings.validation.disposable_domains:
            await redis.sadd("disposable_domains", *settings.validation.disposable_domains)
        logger.info(f"📦 Cached {len(settings.validation.disposable_domains)} disposable domains")
    except Exception as e:
        logger.error(f"Failed to cache disposable domains: {str(e)}")

async def background_tasks():
    while True:
        try:
            logger.debug("Running background maintenance tasks")
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            break

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
    redoc_url=None,  # ← DESHABILITAR ReDoc por defecto
    openapi_url="/openapi.json" if settings.documentation.enabled else None,
    lifespan=lifespan,
    openapi_tags=[
        {"name": "Authentication", "description": "Login, registro y manejo de tokens"},
        {"name": "Validation", "description": "Validación individual y múltiple de emails"},
        {"name": "Billing", "description": "Gestión de planes y facturación"},
    ],
)

# Sobrescribir ReDoc con CDN estable
@app.get("/redoc", include_in_schema=False)
async def redoc_html():
    """ReDoc documentation with stable CDN."""
    return HTMLResponse(f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>{app.title} - ReDoc</title>
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
        <redoc spec-url="/openapi.json"></redoc>
        <script src="https://cdn.redoc.ly/redoc/v2.1.3/bundles/redoc.standalone.js"></script>
    </body>
    </html>
    """)

# Example Pydantic models for validation endpoint
class EmailValidationRequest(BaseModel):
    email: EmailStr

class EmailValidationResponse(BaseModel):
    email: EmailStr
    valid: bool
    reason: str

@app.post("/validate/email", tags=["Validation"], response_model=EmailValidationResponse, summary="Valida un único email")
async def validate_email(payload: EmailValidationRequest = Body(..., example={"email": "usuario@ejemplo.com"})):
    # Aquí pondrías tu lógica real de validación
    return EmailValidationResponse(email=payload.email, valid=True, reason="Email válido y activo")

# Health and Redis checks
@app.get("/healthcheck", include_in_schema=False)
@app.head("/healthcheck", include_in_schema=False)
async def healthcheck():
    return {"status": "ok"}

@app.get("/redis-check", include_in_schema=False)
async def redis_check(request: Request):
    try:
        visits = await request.app.state.redis.incr("visits")
        return {"status": "ok", "visits": visits}
    except Exception as e:
        logger.error(f"Redis check failed: {str(e)}")
        return JSONResponse(status_code=500, content={"status": "error", "detail": "Redis unavailable"})

# Middleware setup
app.add_middleware(LoggingMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware, environment=settings.environment.value)
app.add_middleware(HistoricalKeyMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.security.cors_origins,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key", "Authorization"],
    allow_credentials=settings.security.https_redirect,
    max_age=86400,
)
if settings.monitoring.metrics_enabled and settings.environment != EnvironmentEnum.TESTING:
    app.add_middleware(MetricsMiddleware)
app.middleware("http")(metrics_middleware)

# Register routers with tags
app.include_router(auth_router, prefix="/auth", tags=["Authentication"])
app.include_router(validation_router, prefix="/validate", tags=["Validation"])
app.include_router(validation_router, tags=["Validation (alias)"], include_in_schema=False)  # Alias without schema
app.include_router(test_routes.router, prefix="/test", tags=["Security Tests"], include_in_schema=settings.enable_test_routes)
app.include_router(api_keys_router)
app.include_router(billing_routes.router)
app.include_router(jobs_router)
app.include_router(jobs_webhooks_router)

# Exception handlers and metrics
register_exception_handlers(app)
instrument_app(app)
mount_metrics_endpoint(app)

# Custom OpenAPI
from fastapi.openapi.utils import get_openapi

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="Email Validation API — Enterprise-grade Email Verification",
        version="2.5.0",
        description=(
            "API robusta y segura para validación y verificación de correos electrónicos.\n"
            "Soporta verificación individual y en lote, detección de brechas, y autenticación JWT.\n"
            "Cumple con GDPR y dispone de planes de pago flexibles."
        ),
        routes=app.routes,
        contact=settings.documentation.contact,
    )
    if "components" not in openapi_schema:
        openapi_schema["components"] = {}
    if "securitySchemes" not in openapi_schema["components"]:
        openapi_schema["components"]["securitySchemes"] = {}
    openapi_schema["components"]["securitySchemes"]["Bearer"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    }
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

# Debug logs
print(f"ENVIRONMENT env var: {os.getenv('ENVIRONMENT')}")
print(f"settings.environment: {settings.environment} ({type(settings.environment)})")
print("Stripe premium plan:", settings.stripe.premium_plan_id)
print("Stripe enterprise plan:", settings.stripe.enterprise_plan_id)
print("Stripe key:", settings.stripe.secret_key.get_secret_value()[:10] + "...")

# Entrypoint
if __name__ == "__main__":
    import uvicorn
    config = uvicorn.Config(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info" if settings.environment == EnvironmentEnum.PRODUCTION else "debug",
        timeout_keep_alive=30,
        limit_concurrency=1000,
        loop="uvloop",
        http="httptools",
    )
    logger.info("🔄 Uvicorn starting...")
    logger.info("🌐 Access URL: http://localhost:8000")
    logger.info("📚 Docs: http://localhost:8000/docs")
    uvicorn.Server(config).run()
