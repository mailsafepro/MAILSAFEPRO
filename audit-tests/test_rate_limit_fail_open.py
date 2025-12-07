"""
Test: Rate Limiting Fail-Open Vulnerability

Verifica que el rate limiting no se bypassa cuando Redis falla.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock
from app.rate_limiting.distributed_limiter import DistributedRateLimiter
import asyncio


@pytest.mark.asyncio
async def test_rate_limit_bypass_on_redis_failure():
    """
    Demuestra que el rate limiting se bypassa cuando Redis falla.
    
    PROBLEMA: Cuando Redis falla, el rate limiting retorna (True, 1),
    permitiendo todas las requests. Esto es un bypass de seguridad.
    """
    redis_mock = AsyncMock()
    
    # Simular fallo de Redis (script registration falla)
    redis_mock.register_script.side_effect = Exception("Redis connection failed")
    
    limiter = DistributedRateLimiter(redis_mock)
    
    # Simular 100 requests cuando Redis está caído
    # Todas deberían ser bloqueadas (fail-closed) o al menos limitadas localmente
    allowed_count = 0
    for i in range(100):
        allowed, remaining = await limiter.check_limit("user:123", limit=10, window=60)
        if allowed:
            allowed_count += 1
    
    # ❌ VULNERABILIDAD: Todas las requests son permitidas
    # Esto permite abuso ilimitado durante fallos de Redis
    assert allowed_count == 100, (
        f"❌ VULNERABILIDAD: {allowed_count}/100 requests permitidas cuando Redis falla. "
        "Todas deberían ser bloqueadas (fail-closed) o limitadas localmente."
    )


@pytest.mark.asyncio
async def test_rate_limit_should_fail_closed():
    """
    Verifica que el rate limiting implementa fail-closed cuando Redis falla.
    """
    redis_mock = AsyncMock()
    redis_mock.register_script.side_effect = Exception("Redis down")
    
    limiter = DistributedRateLimiter(redis_mock)
    
    # Primera request: debería ser bloqueada (fail-closed)
    allowed, remaining = await limiter.check_limit("user:123", limit=10, window=60)
    
    # ❌ ACTUAL: allowed=True (fail-open)
    # ✅ ESPERADO: allowed=False (fail-closed)
    assert allowed is False, (
        "❌ Rate limiting debe implementar fail-closed cuando Redis falla. "
        "Actualmente implementa fail-open (vulnerabilidad)."
    )


@pytest.mark.asyncio
async def test_global_rate_limit_fail_open():
    """
    Verifica que el rate limiting global también tiene el problema fail-open.
    """
    from app.main import global_ip_rate_limit_middleware
    from fastapi import Request
    from fastapi.responses import JSONResponse
    from unittest.mock import AsyncMock
    
    # Crear request mock
    request = MagicMock(spec=Request)
    request.url.path = "/validate/email"
    request.client.host = "192.168.1.1"
    request.app.state.redis = None  # Redis no disponible
    request.app.state.redis_available = False
    
    # Mock de call_next
    async def call_next(req):
        return JSONResponse(content={"status": "ok"})
    
    # Ejecutar middleware
    response = await global_ip_rate_limit_middleware(request, call_next)
    
    # ❌ PROBLEMA: Request es permitida cuando Redis no está disponible
    # ✅ ESPERADO: Request debería ser bloqueada o al menos limitada localmente
    assert response.status_code == 200, (
        "❌ Global rate limiting permite requests cuando Redis falla (fail-open). "
        "Debería implementar fail-closed o límite local."
    )


@pytest.mark.asyncio
async def test_rate_limit_with_redis_available():
    """
    Verifica que el rate limiting funciona correctamente cuando Redis está disponible.
    """
    redis_mock = AsyncMock()
    
    # Mock de script de Lua que retorna (allowed, remaining)
    script_mock = AsyncMock()
    script_mock.return_value = [1, 9]  # Allowed=True, remaining=9
    
    redis_mock.register_script.return_value = script_mock
    
    limiter = DistributedRateLimiter(redis_mock)
    
    allowed, remaining = await limiter.check_limit("user:123", limit=10, window=60)
    
    # Cuando Redis funciona, debe retornar el resultado del script
    assert allowed is True
    assert remaining == 9
    
    # Verificar que el script fue llamado
    script_mock.assert_called_once()

