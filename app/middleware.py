# middleware.py — versión corregida y endurecida (v2)

from __future__ import annotations

import re
import hashlib
import uuid
import time
import json
import logging
import asyncio
from typing import Optional, Dict, Any, List

from fastapi import Request, status, HTTPException
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import ClientDisconnect
from starlette.responses import Response
from redis.asyncio import Redis
from jose import jwt

from app.logger import logger
from app.config import settings, EnvironmentEnum
from app.metrics import metrics_recorder
from app.utils import get_user_plan_safe, add_security_headers_to_response
from app.dynamic_quotas import adjust_quotas
from app.auth import _jwt_verify_key

# -----------------------------
# Constantes y patrones de seguridad
# -----------------------------

SAFE_CONTENT_TYPES = {
    "application/json",
    "application/json; charset=utf-8",
}

# Patrón XSS compilado una vez (mejor precisión, menos falsos positivos)
XSS_PATTERN_IMPROVED = re.compile(
    rb"("
    rb"<\s*script[>\s]|"
    rb"<\s*iframe[>\s]|"
    rb"javascript\s*:|"
    rb"onerror\s*=|"
    rb"onload\s*=|"
    rb"onclick\s*=|"
    rb"eval\s*\(|"
    rb"<\s*img[^>]+onerror|"
    rb"expression\s*\("
    rb")",
    re.IGNORECASE,
)

MAX_BODY_SIZE = 10 * 1024 * 1024  # 10 MB

# Script Lua atómico de rate limit (ventana fija)
LUA_RATE_LIMIT = """
local key = KEYS[1]
local window = tonumber(ARGV[1])
local current = redis.call('INCR', key)
if current == 1 then
  redis.call('EXPIRE', key, window)
end
local ttl = redis.call('TTL', key)
return {current, ttl}
"""

# -----------------------------
# Middlewares
# -----------------------------

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, environment: EnvironmentEnum = EnvironmentEnum.PRODUCTION):
        super().__init__(app)
        self.environment = environment

    async def dispatch(self, request: Request, call_next) -> Response:
        # 1) Excluir endpoint de prueba
        if request.url.path == "/validate/email-test":
            return await call_next(request)
        
        # 1.5) Excluir healthchecks de validaciones y redirects
        health_paths = {"/healthcheck", "/auth/health/auth", "/validate/health", "/health"}
        if request.url.path in health_paths:
            response = await call_next(request)
            return response
        
        # 2) Validación Content-Type
        if request.method in ("POST", "PUT", "PATCH"):
            invalid = await self._validate_content_type(request)
            if invalid:
                return invalid
        
        # 3) Forzar HTTPS en producción (excepto /metrics y healthchecks ya excluidos)
        if (
            self.environment == EnvironmentEnum.PRODUCTION
            and request.url.scheme != "https"
            and not request.url.path.startswith("/metrics")
        ):
            url_https = str(request.url.replace(scheme="https"))
            return RedirectResponse(url=url_https, status_code=307)
        
        # 4) Validación XSS por patrón
        xss_resp = await self._check_xss(request)
        if xss_resp:
            client_plan = await get_user_plan_safe(request, request.app.state.redis)
            metrics_recorder.record_error(
                error_type="security_xss_attempt",
                severity="warning",
                component="security_middleware"
            )
            return xss_resp
        
        # 5) Continuar
        response = await call_next(request)
        
        # 6) Agregar cabeceras de seguridad con CSP diferenciada
        self._add_security_headers(response, request.url.path)
        return response


    async def _validate_content_type(self, request: Request) -> Optional[JSONResponse]:
        content_type = (request.headers.get("Content-Type") or "").lower()
        if request.method in ("POST", "PUT", "PATCH"):
            if not any(content_type.startswith(allowed) for allowed in SAFE_CONTENT_TYPES):
                return JSONResponse(
                    status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                    content={"detail": "Unsupported Media Type. Only 'application/json' is accepted."},
                )
        return None

    async def _check_xss(self, request: Request) -> Optional[JSONResponse]:
        try:
            if request.method not in ("POST", "PUT", "PATCH"):
                return None

            # Leer body por streaming y limitar tamaño
            body_size = 0
            body_chunks: List[bytes] = []
            try:
                async for chunk in request.stream():
                    body_size += len(chunk)
                    if body_size > MAX_BODY_SIZE:
                        logger.warning(f"Request body too large from {request.client.host}: {body_size} bytes")
                        return JSONResponse(
                            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            content={"detail": "Request body too large"},
                        )
                    body_chunks.append(chunk)
            except ClientDisconnect:
                return None

            body_bytes = b"".join(body_chunks)

            # Detección XSS
            if XSS_PATTERN_IMPROVED.search(body_bytes):
                logger.warning(
                    "XSS attempt detected",
                    extra={
                        "client_ip": request.client.host if request.client else None,
                        "path": request.url.path,
                        "request_id": getattr(request.state, "correlation_id", "unknown"),
                    },
                )
                request_id = getattr(request.state, "correlation_id", "unknown")
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={"detail": "Invalid request content"},
                    headers={"X-Request-ID": request_id},
                )

            # Reconstruir body para el siguiente handler
            request._body = body_bytes  # noqa: SLF001 (acceso interno controlado)
            async def new_receive() -> dict:
                return {"type": "http.request", "body": body_bytes, "more_body": False}
            request._receive = new_receive  # noqa: SLF001

            return None

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Security check error: {type(e).__name__}", exc_info=True)
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"detail": "Security check failed"},
            )

    def _add_security_headers(self, response: Response, path: str) -> None:
        # CSP específica para /docs (Swagger UI)
        csp_docs = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com data:; "
            "img-src 'self' data: https: https://fastapi.tiangolo.com; "  # ← Añadido https: y fastapi.tiangolo.com
            "connect-src 'self'; "
            "frame-src 'self'; "
            "worker-src 'self'"
        )
        
        # CSP por defecto (restrictiva)
        csp_default = (
            "default-src 'self'; "
            "script-src 'self' https://cdn.jsdelivr.net; "
            "style-src 'self' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com data:; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-src 'self'; "
            "worker-src 'self'"
        )
        
        # CSP para /redoc
        csp_redoc = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://cdn.redoc.ly; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com https://fonts.googleapis.com data:; "
            "img-src 'self' data: https: https://fastapi.tiangolo.com https://cdn.redoc.ly; "
            "connect-src 'self' https://api.redoc.ly; "
            "worker-src 'self' blob:; "
            "child-src 'self' blob:; "
            "object-src 'none'; "
            "base-uri 'self'"
        )

    
        # Seleccionar CSP según ruta
        if path == "/docs":
            response.headers["Content-Security-Policy"] = csp_docs
        elif path == "/redoc":
            response.headers["Content-Security-Policy"] = csp_redoc
        else:
            response.headers["Content-Security-Policy"] = csp_default

        # Cabeceras comunes; eliminamos X-XSS-Protection (deprecado)
        response.headers.update(
            {
                "X-Content-Type-Options": "nosniff",
                "Permissions-Policy": (
                    "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), "
                    "microphone=(), payment=(), usb=()"
                ),
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
                "X-Frame-Options": "DENY",
            }
        )


class CORSMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        origin = request.headers.get("Origin")
        if request.method == "OPTIONS":
            return self._handle_preflight(origin)
        response = await call_next(request)
        self._add_cors_headers(response, origin)
        return response

    def _handle_preflight(self, origin: Optional[str]) -> JSONResponse:
        headers = self._build_cors_headers(origin)
        response = JSONResponse(content={"status": "ok"}, headers=headers)
        add_security_headers_to_response(response)  # refuerzo de seguridad
        return response

    def _add_cors_headers(self, response: JSONResponse, origin: Optional[str]) -> None:
        headers = self._build_cors_headers(origin)
        response.headers.update(headers)

    def _build_cors_headers(self, origin: Optional[str]) -> dict:
        allowed_origins = settings.security.cors_origins
        headers = {
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, X-API-Key, Authorization",
            "Access-Control-Max-Age": "86400",
            "Access-Control-Allow-Credentials": "true" if settings.security.https_redirect else "false",
            "Access-Control-Expose-Headers": "X-Request-ID, X-RateLimit-*",
        }
        if origin and origin in allowed_origins:
            headers["Access-Control-Allow-Origin"] = origin
        return headers


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        # Sólo aplicar a /validate/email
        if not request.url.path.startswith("/validate/email"):
            return await call_next(request)

        # Headers de autenticación
        api_key = request.headers.get("X-API-Key")
        auth_header = request.headers.get("Authorization")
        redis: Redis = request.app.state.redis

        # Determinar identidad/plan para Rate Limit: API Key o Bearer
        if api_key:
            # Flujo API Key (tal y como tenías)
            plan = await get_user_plan_safe(request, redis)
            client_id = api_key  # no exponer valor real en logs/respuestas
        elif auth_header and auth_header.startswith("Bearer "):
            # Flujo JWT Bearer
            token = auth_header.split(" ", 1)[1]
            try:
                # Requiere helper de auth.py (_jwt_verify_key) y jose.jwt
                key = _jwt_verify_key(token)
                payload = jwt.decode(
                    token,
                    key,
                    algorithms=[settings.jwt.algorithm],
                    audience=settings.jwt.audience,
                    issuer=settings.jwt.issuer,
                    options={"require_exp": True, "require_nbf": True},
                )
                client_id = f"user:{payload.get('sub', 'unknown')}"
                plan = str(payload.get("plan", "FREE")).upper()
            except Exception:
                # Token inválido: no bloquees la petición por aquí, deja que el endpoint falle con 401
                return await call_next(request)
        else:
            # Sin X-API-Key ni Bearer → no aplicar rate limit aquí
            return await call_next(request)


        # Límite estático por plan
        cfg = settings.rate_limit_config.get(plan, settings.rate_limit_config["FREE"])
        static_count = cfg["count"]
        window = cfg["window"]

        # Override dinámico
        dyn = await redis.get(f"rate_limit:{client_id}")
        try:
            if dyn is None:
                limit = static_count
            elif isinstance(dyn, bytes):
                dyn_str = dyn.decode("utf-8", errors="ignore").strip()
                limit = int(dyn_str) if dyn_str and dyn_str.isdigit() else static_count
            else:
                dyn_str = str(dyn).strip()
                limit = int(dyn_str) if dyn_str and dyn_str.isdigit() else static_count
        except (ValueError, TypeError, AttributeError) as e:
            logger.warning(f"Invalid rate limit value: {dyn}, using default: {static_count}. Error: {e}")
            limit = static_count

        # Script Lua: contador + TTL
        quota_key = f"quota:{plan}:{hashlib.sha256(client_id.encode()).hexdigest()}"
        try:
            result = await redis.eval(LUA_RATE_LIMIT, 1, quota_key, window)
            if isinstance(result, (list, tuple)) and len(result) >= 2:
                current_val, ttl_val = result[0], result[1]
                try:
                    current_count = int(current_val)
                    ttl_remaining = int(ttl_val)
                except (TypeError, ValueError):
                    current_count, ttl_remaining = 1, window
            else:
                logger.warning(f"Unexpected result format from Redis eval: {result}")
                current_count, ttl_remaining = 1, window
        except Exception as e:
            logger.error(f"Rate limit script error: {str(e)}")
            current_count, ttl_remaining = 1, window
            asyncio.create_task(adjust_quotas(client_id, redis))

        # Normalizar TTL negativo (-1/-2) a ventana
        if ttl_remaining is None or ttl_remaining < 0:
            ttl_remaining = window

        # Cabeceras de rate limit (categóricas)
        remaining_pct = max((limit - current_count) / limit, 0) if limit > 0 else 0
        if remaining_pct > 0.5:
            remaining_category = "high"
        elif remaining_pct > 0.2:
            remaining_category = "medium"
        else:
            remaining_category = "low"

        headers = {
            "X-RateLimit-Limit": str(limit),
            "X-RateLimit-Remaining-Category": remaining_category,
            "X-RateLimit-Reset": str(ttl_remaining),
        }
        if remaining_pct <= 0.2:
            headers["X-RateLimit-Warning"] = "approaching limit"

        # Exceso de cuota
        if current_count > limit:
            logger.warning(
                "Quota exceeded",
                extra={
                    "client_hash": hashlib.sha256(client_id.encode()).hexdigest()[:8],
                    "plan": plan,
                    "current": current_count,
                    "limit": limit,
                },
            )
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Rate limit exceeded"},
                headers=headers,
            )

        # Continuar
        response = await call_next(request)
        response.headers.update(headers)
        return response


class HistoricalKeyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        # Sólo endpoints de validación
        if request.url.path.startswith("/validate/email"):
            api_key = request.headers.get("X-API-Key")
            if api_key:
                redis: Redis = request.app.state.redis
                key_hash = hashlib.sha256(api_key.encode()).hexdigest()
                redis_key = f"key:{key_hash}"
                try:
                    key_data = await redis.get(redis_key)
                    if key_data is None:
                        return await call_next(request)

                    key_str = key_data.decode("utf-8", errors="ignore") if isinstance(key_data, bytes) else str(key_data)
                    if "deprecated" in key_str.lower():
                        client_plan = await get_user_plan_safe(request, redis)
                        metrics_recorder.record_error(
                            error_type="security_deprecated_key",
                            severity="warning",
                            component="historical_key_middleware"
                        )
                        return JSONResponse(status_code=status.HTTP_410_GONE, content={"detail": "Deprecated API Key"})
                except Exception as e:
                    logger.exception(f"Error checking deprecated key: {e}")
                    return await call_next(request)

        return await call_next(request)


class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.correlation_id = request_id
        start_time = time.time()

        log_context = {
            "request_id": request_id,
            "client_ip": request.client.host if request.client else None,
            "method": request.method,
            "path": request.url.path,
            "user_agent": request.headers.get("user-agent"),
        }
        safe_context = {**log_context, "request_id": request_id or "unknown"}

        with logger.contextualize(**safe_context):
            if settings.debug:
                logger.debug("Request started")
            try:
                response = await call_next(request)
            except Exception as e:
                logger.error(f"Request failed: {type(e).__name__} - {str(e)}")
                raise
            process_time = (time.time() - start_time) * 1000
            if settings.debug:
                logger.debug("Request completed", status_code=response.status_code, process_time=f"{process_time:.2f}ms")
            response.headers["X-Request-ID"] = request_id
            return response


class MetricsMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response: Response = JSONResponse(
            content={"detail": "Internal server error"},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
        try:
            response = await call_next(request)
            return response
        finally:
            try:
    # Las métricas HTTP se registran automáticamente por el metrics_middleware
    # de metrics.py, no es necesario registrarlas manualmente aquí
                pass
            except Exception as e:
                logger.error(f"Metrics error: {str(e)}")

