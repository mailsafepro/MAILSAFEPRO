"""
Test: Excepciones JWT no importadas

Verifica que JWTError y JWTClaimsError están importados correctamente.
"""
import pytest
import inspect
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import Request, HTTPException


def test_jwt_exceptions_imported():
    """
    Verifica que JWTError y JWTClaimsError están importados en auth.py.
    """
    import app.auth as auth_module
    
    # Leer el archivo fuente
    import os
    auth_file = os.path.join(os.path.dirname(auth_module.__file__), "auth.py")
    
    with open(auth_file, "r") as f:
        content = f.read()
    
    # Verificar imports
    has_jwt_error_import = "JWTError" in content and "from jwt.exceptions import" in content
    has_jwt_claims_error_import = "JWTClaimsError" in content and "from jwt.exceptions import" in content
    
    # Verificar uso
    uses_jwt_error = "JWTError" in content and "except" in content
    uses_jwt_claims_error = "JWTClaimsError" in content and "except" in content
    
    if uses_jwt_error and not has_jwt_error_import:
        pytest.fail(
            "❌ JWTError se usa pero NO está importado. "
            "Esto causará NameError en runtime cuando se procesen tokens inválidos."
        )
    
    if uses_jwt_claims_error and not has_jwt_claims_error_import:
        pytest.fail(
            "❌ JWTClaimsError se usa pero NO está importado. "
            "Esto causará NameError en runtime cuando se procesen tokens con claims inválidos."
        )


@pytest.mark.asyncio
async def test_refresh_token_with_invalid_token_handles_jwt_error():
    """
    Verifica que refresh_token maneja correctamente tokens inválidos.
    
    Si JWTError no está importado, esto causará NameError en lugar de HTTPException.
    """
    from app.auth import refresh_token
    from redis.asyncio import Redis
    
    request = MagicMock(spec=Request)
    request.headers = {"Authorization": "Bearer invalid.token.here"}
    request.json = AsyncMock(return_value={})
    
    redis_mock = AsyncMock(spec=Redis)
    
    # Esto debería lanzar HTTPException(401), NO NameError
    try:
        await refresh_token(request, redis=redis_mock)
        pytest.fail("Expected HTTPException but got no exception")
    except HTTPException as e:
        assert e.status_code == 401
        assert "Invalid" in str(e.detail) or "token" in str(e.detail).lower()
    except NameError as e:
        pytest.fail(
            f"❌ NameError lanzado (JWTError no importado): {e}\n"
            "Esto indica que JWTError o JWTClaimsError no están importados."
        )
    except Exception as e:
        # Otros errores son aceptables (p. ej., si el token no puede decodificarse)
        # pero NameError NO es aceptable
        if "JWTError" in str(e) or "JWTClaimsError" in str(e) or "not defined" in str(e):
            pytest.fail(f"❌ Error de importación: {e}")


@pytest.mark.asyncio
async def test_logout_with_invalid_token_handles_jwt_error():
    """
    Verifica que logout maneja correctamente tokens inválidos.
    """
    from app.auth import logout
    from redis.asyncio import Redis
    
    request = MagicMock(spec=Request)
    request.headers = {"Authorization": "Bearer completely.invalid.token"}
    request.json = AsyncMock(return_value={})
    
    redis_mock = AsyncMock(spec=Redis)
    
    try:
        result = await logout(request, redis=redis_mock)
        # Logout es idempotente, puede retornar éxito incluso con token inválido
        assert isinstance(result, dict)
    except NameError as e:
        pytest.fail(
            f"❌ NameError lanzado (JWTError no importado): {e}\n"
            "Esto indica que JWTError o JWTClaimsError no están importados en logout."
        )
    except Exception as e:
        if "JWTError" in str(e) or "JWTClaimsError" in str(e) or "not defined" in str(e):
            pytest.fail(f"❌ Error de importación: {e}")


def test_jwt_exceptions_in_imports():
    """
    Verifica que las excepciones JWT están en los imports.
    """
    import app.auth
    
    # Verificar que el módulo puede importarse sin errores
    assert hasattr(app.auth, "InvalidTokenError")
    assert hasattr(app.auth, "ExpiredSignatureError")
    
    # Verificar que JWTError y JWTClaimsError están disponibles
    # (si no están importados, esto fallará)
    try:
        from jwt.exceptions import JWTError, JWTClaimsError
        # Verificar que se usan en el código
        import inspect
        source = inspect.getsource(app.auth.refresh_token)
        if "JWTError" in source or "JWTClaimsError" in source:
            # Deben estar importados
            assert "JWTError" in dir(app.auth) or "from jwt.exceptions import" in inspect.getsourcefile(app.auth.refresh_token)
    except ImportError:
        pytest.fail("❌ jwt.exceptions no puede importarse - verificar instalación de PyJWT")

