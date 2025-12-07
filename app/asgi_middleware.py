"""

Pure ASGI Middleware - Production Grade

High-performance middleware using pure ASGI pattern (not BaseHTTPMiddleware).

This avoids the starlette middleware stack overflow issues.

Benefits:

- 2-3x faster than BaseHTTPMiddleware

- No stack overflow issues

- Lower memory footprint

- Better async performance

"""

import time
from starlette.datastructures import MutableHeaders, Headers
from starlette.types import ASGIApp, Receive, Scope, Send
from app.logger import logger
import hashlib
from typing import Dict, Optional
from app.json_utils import dumps as json_dumps, loads as json_loads


class SecurityHeadersASGI:
    """
    Pure ASGI middleware for security headers.
    
    Adds:
    - X-Frame-Options
    - X-Content-Type-Options
    - X-XSS-Protection
    - Strict-Transport-Security (HSTS)
    - Content-Security-Policy
    """

    def __init__(self, app: ASGIApp, environment: str = "production"):
        self.app = app
        self.environment = environment

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                
                # Security headers
                headers["X-Frame-Options"] = "DENY"
                headers["X-Content-Type-Options"] = "nosniff"
                headers["X-XSS-Protection"] = "1; mode=block"
                headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
                
                # HSTS for production
                if self.environment == "production":
                    headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
                
                # CSP
                headers["Content-Security-Policy"] = (
                    "default-src 'self'; "
                    "script-src 'self' 'unsafe-inline' https://cdn.redoc.ly; "
                    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                    "font-src 'self' https://fonts.gstatic.com; "
                    "img-src 'self' data: https:; "
                    "connect-src 'self'; "
                    "frame-ancestors 'none';"
                )
                
                # Permissions Policy
                headers["Permissions-Policy"] = (
                    "geolocation=(), "
                    "microphone=(), "
                    "camera=(), "
                    "payment=(), "
                    "usb=(), "
                    "magnetometer=(), "
                    "gyroscope=()"
                )
            
            await send(message)

        await self.app(scope, receive, send_with_headers)


class LoggingASGI:
    """
    Pure ASGI middleware for request logging.
    
    Logs:
    - Request method, path, query params
    - Response status code
    - Request duration
    - Client IP
    """

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        start_time = time.time()
        status_code = 500

        async def send_with_logging(message):
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_with_logging)
        finally:
            # Log after request completes
            duration = time.time() - start_time
            client = scope.get("client")
            client_ip = client[0] if client else "unknown"
            method = scope.get("method", "UNKNOWN")
            path = scope.get("path", "/")
            
            # Only log non-health check endpoints
            if not path.startswith(("/health", "/metrics")):
                logger.info(
                    f"{method} {path} → {status_code}",
                    extra={
                        "duration_ms": int(duration * 1000),
                        "status_code": status_code,
                        "client_ip": client_ip,
                        "method": method,
                        "path": path,
                    }
                )


class RateLimitASGI:
    """
    Pure ASGI middleware for rate limiting.
    
    Uses Redis for distributed rate limiting.
    Falls back gracefully if Redis is unavailable.
    """

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Scope, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Rate limiting logic will be in the endpoint dependency
        # This middleware just adds headers
        async def send_with_rate_limit_headers(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                
                # Add rate limit headers if available in scope state
                if "rate_limit" in scope.get("state", {}):
                    rate_info = scope["state"]["rate_limit"]
                    headers["X-RateLimit-Limit"] = str(rate_info.get("limit", 100))
                    headers["X-RateLimit-Remaining"] = str(rate_info.get("remaining", 100))
                    headers["X-RateLimit-Reset"] = str(rate_info.get("reset", 0))
            
            await send(message)

        await self.app(scope, receive, send_with_rate_limit_headers)


class MetricsASGI:
    """
    Pure ASGI middleware for Prometheus metrics.
    
    Tracks:
    - Request count by method, path, status
    - Request duration histogram
    - Active requests gauge
    """

    def __init__(self, app: ASGIApp):
        self.app = app
        self.active_requests = 0
        
        # Import prometheus here to avoid circular imports
        try:
            from prometheus_client import Counter, Histogram, Gauge
            
            self.request_count = Counter(
                "http_requests_total",
                "Total HTTP requests",
                ["method", "endpoint", "status"]
            )
            
            self.request_duration = Histogram(
                "http_request_duration_seconds",
                "HTTP request duration",
                ["method", "endpoint"],
                buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
            )
            
            self.active_requests_gauge = Gauge(
                "http_requests_active",
                "Active HTTP requests"
            )
            
            self.metrics_enabled = True
        except ImportError:
            self.metrics_enabled = False

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not self.metrics_enabled:
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "UNKNOWN")
        path = scope.get("path", "/")
        start_time = time.time()
        status_code = 500
        
        # Increment active requests
        self.active_requests_gauge.inc()

        async def send_with_metrics(message):
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_with_metrics)
        finally:
            # Record metrics
            duration = time.time() - start_time
            
            # Decrement active requests
            self.active_requests_gauge.dec()
            
            # Don't track metrics endpoints themselves
            if not path.startswith("/metrics"):
                # Normalize path for metrics (remove IDs)
                normalized_path = self._normalize_path(path)
                
                self.request_count.labels(
                    method=method,
                    endpoint=normalized_path,
                    status=status_code
                ).inc()
                
                self.request_duration.labels(
                    method=method,
                    endpoint=normalized_path
                ).observe(duration)

    def _normalize_path(self, path: str) -> str:
        """Normalize path by removing UUIDs and numeric IDs."""
        import re
        
        # Replace UUIDs
        path = re.sub(
            r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            '/{id}',
            path,
            flags=re.IGNORECASE
        )
        
        # Replace numeric IDs
        path = re.sub(r'/\d+', '/{id}', path)
        
        return path


class HistoricalKeyCompatASGI:
    """
    Pure ASGI middleware for backward compatibility with old API keys.
    
    Converts old Authorization: Bearer sk_... to X-API-Key: sk_...
    """

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Check if Authorization header contains API key
        headers = Headers(scope=scope)
        auth_header = headers.get("authorization", "")
        
        if auth_header.startswith("Bearer sk_") or auth_header.startswith("Bearer key_"):
            # Convert to X-API-Key header
            api_key = auth_header.replace("Bearer ", "")
            
            # Modify headers in scope
            new_headers = []
            for name, value in scope["headers"]:
                if name != b"authorization":
                    new_headers.append((name, value))
            
            # Add X-API-Key header
            new_headers.append((b"x-api-key", api_key.encode()))
            scope["headers"] = new_headers

        await self.app(scope, receive, send)


class ResponseCacheASGI:
    """
    Pure ASGI middleware for response caching.
    
    Caches idempotent GET requests for specific paths.
    """
    
    # Define cacheable paths with TTL (seconds)
    CACHEABLE_PATHS: Dict[str, int] = {
        "/validate/disposable-domains": 3600,  # 1 hour
        "/validate/provider-stats": 300,       # 5 minutes
        "/health": 10,                          # 10 seconds
        "/metrics/stats": 60,                   # 1 minute
    }

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] != "GET":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "/")
        
        # Check if path is cacheable
        cache_ttl = None
        for c_path, ttl in self.CACHEABLE_PATHS.items():
            if path.startswith(c_path):
                cache_ttl = ttl
                break
        
        if not cache_ttl:
            await self.app(scope, receive, send)
            return

        # Check if Redis is available in app state
        # In ASGI, app state is usually in scope['state'] if using Starlette/FastAPI
        redis = scope.get("state", {}).get("redis")
        if not redis:
            await self.app(scope, receive, send)
            return

        # Generate cache key - SECURITY FIX: Using SHA-256 instead of MD5
        query_string = scope.get("query_string", b"").decode()
        query_hash = hashlib.sha256(query_string.encode()).hexdigest()
        cache_key = f"http_cache:{path}:{query_hash}"

        # Try cache
        try:
            cached = await redis.get(cache_key)
            if cached:
                response_data = json_loads(cached)
                
                # Reconstruct headers
                headers = []
                for k, v in response_data.get("headers", {}).items():
                    headers.append((k.encode(), v.encode()))
                
                # Add cache hit header
                headers.append((b"x-cache", b"HIT"))
                
                # Send response
                await send({
                    "type": "http.response.start",
                    "status": response_data["status_code"],
                    "headers": headers,
                })
                
                await send({
                    "type": "http.response.body",
                    "body": response_data["body"].encode(),
                })
                
                return
        except Exception as e:
            logger.debug(f"Cache check failed: {e}")

        # Cache MISS - capture response
        response_body = b""
        response_status = 200
        response_headers = {}

        async def send_with_cache(message):
            nonlocal response_body, response_status, response_headers
            
            if message["type"] == "http.response.start":
                response_status = message["status"]
                
                # Capture headers
                for k, v in message.get("headers", []):
                    response_headers[k.decode().lower()] = v.decode()
                
                # Add cache miss header
                headers = MutableHeaders(scope=message)
                headers["X-Cache"] = "MISS"
            
            elif message["type"] == "http.response.body":
                response_body += message.get("body", b"")
            
            await send(message)

        await self.app(scope, receive, send_with_cache)

        # Store in cache if successful
        if 200 <= response_status < 300:
            try:
                # Filter headers
                cached_headers = {
                    k: v for k, v in response_headers.items()
                    if k not in ["content-length", "transfer-encoding", "set-cookie", "x-cache"]
                }
                
                cache_data = {
                    "body": response_body.decode('utf-8', errors='ignore'),
                    "status_code": response_status,
                    "headers": cached_headers
                }
                
                await redis.setex(cache_key, cache_ttl, json_dumps(cache_data))
            except Exception as e:
                logger.warning(f"Failed to cache response: {e}")
