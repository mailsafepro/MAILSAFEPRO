"""
Test: Revocación de Tokens

Verifica que los tokens revocados no pueden usarse.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import Request
from datetime import datetime, timedelta, timezone
import jwt
from app.auth import (
    create_access_token,
    blacklist_token,
    get_current_client,
    logout,
)
from app.config import settings


@pytest.mark.asyncio
async def test_revoked_token_cannot_be_used():
    """
    Verifica que un token revocado no puede usarse para autenticación.
    """
    from app.models import TokenData
    from redis.asyncio import Redis
    
    # 1. Crear token
    user_id = "test_user_123"
    access_token = create_access_token({"sub": user_id, "email": "test@example.com"}, plan="FREE")
    
    # 2. Verificar que el token funciona inicialmente
    redis_mock = AsyncMock(spec=Redis)
    redis_mock.exists.return_value = 0  # Token no está en blacklist
    
    # Decodificar token para obtener jti y exp
    payload = jwt.decode(access_token, options={"verify_signature": False})
    jti = payload.get("jti")
    exp = payload.get("exp")
    
    # 3. Revocar token (simular logout)
    await blacklist_token(jti, exp, redis_mock)
    
    # 4. Verificar que el token está en blacklist
    redis_mock.exists.return_value = 1  # Token ahora está en blacklist
    
    # 5. Intentar usar token revocado (debe fallar)
    request = MagicMock(spec=Request)
    request.headers = {"Authorization": f"Bearer {access_token}"}
    request.app.state.redis = redis_mock
    
    from app.auth import CustomHTTPBearer
    from fastapi.security import HTTPAuthorizationCredentials
    
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=access_token)
    
    try:
        # Esto debería lanzar HTTPException(401) porque el token está revocado
        await get_current_client(
            security_scopes=MagicMock(),
            credentials=credentials,
            redis=redis_mock
        )
        pytest.fail("Expected HTTPException(401) for revoked token, but got no exception")
    except Exception as e:
        # Debe ser HTTPException con 401
        assert hasattr(e, "status_code"), f"Expected HTTPException, got {type(e)}: {e}"
        assert e.status_code == 401, f"Expected 401, got {e.status_code}"
        assert "revoked" in str(e.detail).lower() or "invalid" in str(e.detail).lower()


@pytest.mark.asyncio
async def test_logout_revokes_token():
    """
    Verifica que logout revoca correctamente el token.
    """
    from redis.asyncio import Redis
    
    # Crear token
    user_id = "test_user_123"
    access_token = create_access_token({"sub": user_id, "email": "test@example.com"}, plan="FREE")
    
    redis_mock = AsyncMock(spec=Redis)
    
    # Mock de blacklist_token
    blacklisted_jtis = set()
    
    async def mock_blacklist(jti, exp, redis):
        blacklisted_jtis.add(jti)
    
    # Ejecutar logout
    request = MagicMock(spec=Request)
    request.headers = {"Authorization": f"Bearer {access_token}"}
    request.json = AsyncMock(return_value={})
    
    with patch("app.auth.blacklist_token", side_effect=mock_blacklist):
        result = await logout(request, redis_mock)
    
    # Verificar que el token fue revocado
    payload = jwt.decode(access_token, options={"verify_signature": False})
    jti = payload.get("jti")
    
    assert jti in blacklisted_jtis, "Token should be blacklisted after logout"
    assert result.get("token_status") in ("revoked", "expired", "none")


@pytest.mark.asyncio
async def test_refresh_token_after_logout_fails():
    """
    Verifica que no se puede refrescar un token después de logout.
    """
    from app.auth import create_refresh_token, store_refresh_token, revoke_refresh_token
    from redis.asyncio import Redis
    
    user_id = "test_user_123"
    refresh_token_str, refresh_exp = create_refresh_token(
        {"sub": user_id, "email": "test@example.com"},
        plan="FREE"
    )
    
    redis_mock = AsyncMock(spec=Redis)
    
    # Guardar refresh token
    payload = jwt.decode(refresh_token_str, options={"verify_signature": False})
    jti = payload.get("jti")
    
    await store_refresh_token(jti, refresh_exp, redis_mock)
    
    # Verificar que existe
    redis_mock.exists.return_value = 1
    
    # Simular logout (revocar refresh token)
    await revoke_refresh_token(jti, redis_mock)
    
    # Verificar que fue revocado
    redis_mock.exists.return_value = 0  # Ya no existe
    
    # Intentar usar refresh token revocado (debe fallar)
    from app.auth import refresh_token
    request = MagicMock(spec=Request)
    request.headers = {"Authorization": f"Bearer {refresh_token_str}"}
    request.json = AsyncMock(return_value={})
    
    try:
        await refresh_token(request, redis_mock)
        pytest.fail("Expected HTTPException(401) for revoked refresh token")
    except Exception as e:
        assert hasattr(e, "status_code")
        assert e.status_code == 401
        assert "revoked" in str(e.detail).lower() or "invalid" in str(e.detail).lower()

