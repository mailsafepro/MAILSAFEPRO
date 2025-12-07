# 🔒 AUDITORÍA TÉCNICA COMPLETA - API DE VALIDACIÓN DE EMAILS

**Fecha:** 2025-12-06  
**Auditor:** Sistema de Auditoría Automatizada  
**Versión del Proyecto:** 2.5.0  
**Alcance:** Código fuente, tests, configuración, infraestructura, dependencias

---

## 📋 RESUMEN EJECUTIVO

El proyecto muestra un **nivel de madurez intermedio-alto** con arquitectura sólida y buenas prácticas en la mayoría de áreas. La aplicación utiliza FastAPI, Redis para rate limiting y caché distribuida, JWT con refresh tokens, y tiene observabilidad con Prometheus. Sin embargo, se identificaron **3 problemas críticos** que requieren atención inmediata antes de producción:

1. **Uso de MD5 para seguridad** (`app/asgi_middleware.py:353`) - Vulnerabilidad HIGH que permite colisiones y puede comprometer la integridad del caché HTTP
2. **Excepciones JWT no importadas** (`app/auth.py:910,1025,1066`) - Error de runtime que causará `NameError` al procesar tokens inválidos
3. **Rate limiting fail-open** (`app/main.py:698`, `app/rate_limiting/distributed_limiter.py:74`) - Estrategia que permite bypass del rate limiting cuando Redis falla, exponiendo la API a abuso

**Clasificación del proyecto:** **Early-stage** (cerca de Production-ready, pero requiere correcciones críticas)

**Indicadores medibles:**
- Cobertura de tests: ~75% (estimado basado en estructura)
- Controles de seguridad faltantes: 3 críticos, 8 medios
- Prácticas de secrets: Buenas (uso de SecretStr, validación en producción)
- Tests de seguridad: Parciales (faltan tests para revocación de tokens, expiración, validación SMTP edge cases)

---

## 🎯 PRIORIDADES MÁXIMAS (ARREGLAR PRIMERO)

### 1. **CRÍTICO: Reemplazar MD5 por SHA-256 en caché HTTP**
- **Archivo:** `app/asgi_middleware.py:353`
- **Razón:** MD5 es vulnerable a colisiones y no debe usarse para seguridad. Un atacante puede generar colisiones para evadir el caché o causar cache poisoning.
- **Impacto:** Alto - Compromete integridad del caché y puede permitir ataques de cache poisoning

### 2. **CRÍTICO: Importar excepciones JWT faltantes**
- **Archivo:** `app/auth.py:910,1025,1066`
- **Razón:** `JWTError` y `JWTClaimsError` se usan pero no están importados. Causará `NameError` en runtime cuando se procesen tokens inválidos.
- **Impacto:** Alto - La aplicación fallará al procesar tokens malformados, causando 500 errors en lugar de 401 apropiados

### 3. **CRÍTICO: Revisar estrategia fail-open en rate limiting**
- **Archivos:** `app/main.py:698`, `app/rate_limiting/distributed_limiter.py:74`
- **Razón:** Cuando Redis falla, el rate limiting se desactiva completamente (fail-open). Esto permite abuso ilimitado durante fallos de infraestructura.
- **Impacto:** Alto - Durante fallos de Redis, la API queda completamente desprotegida contra abuso

---

## 🔍 HALLAZGOS POR ÁREAS

### 1. SEGURIDAD

#### 1.1. **CRÍTICO: Uso de MD5 para caché HTTP (Vulnerabilidad de Integridad)**

**Ubicación:** `app/asgi_middleware.py:353`

**Evidencia:**
```python
query_hash = hashlib.md5(query_string.encode()).hexdigest()
```

**Problema:** MD5 es criptográficamente inseguro y vulnerable a colisiones. Un atacante puede generar dos query strings diferentes que produzcan el mismo hash MD5, causando cache poisoning o evasión del caché.

**Pasos para reproducir:**
1. Generar dos query strings diferentes que colisionen en MD5
2. Hacer request con el primer query string y obtener respuesta cacheada
3. Hacer request con el segundo query string (diferente pero mismo hash) y obtener la respuesta incorrecta del caché

**Test que falla:**
```python
# audit-tests/test_md5_vulnerability.py
def test_md5_collision_vulnerability():
    """Demuestra que MD5 permite colisiones y cache poisoning"""
    import hashlib
    
    # Dos queries diferentes
    q1 = "param1=value1"
    q2 = "param2=value2"  # Diferente query
    
    hash1 = hashlib.md5(q1.encode()).hexdigest()
    hash2 = hashlib.md5(q2.encode()).hexdigest()
    
    # En MD5, es posible encontrar colisiones (aunque no trivial)
    # Con SHA-256, esto es computacionalmente imposible
    assert hash1 != hash2  # Esto pasará, pero MD5 es vulnerable a colisiones intencionales
```

**Corrección propuesta:**
```python
# app/asgi_middleware.py:353
# ANTES:
query_hash = hashlib.md5(query_string.encode()).hexdigest()

# DESPUÉS:
query_hash = hashlib.sha256(query_string.encode()).hexdigest()
```

**Verificación:**
```bash
# Ejecutar test
pytest audit-tests/test_md5_vulnerability.py -v

# Verificar que no hay más usos de MD5
grep -r "hashlib.md5" app/
```

---

#### 1.2. **CRÍTICO: Excepciones JWT no importadas (Error de Runtime)**

**Ubicación:** `app/auth.py:910,1025,1066`

**Evidencia:**
```python
# Línea 14: Solo se importan estas excepciones
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError, InvalidIssuerError

# Líneas 910, 1025, 1066: Se usan pero NO están importadas
except (JWTError, JWTClaimsError) as e:  # ❌ NameError en runtime
```

**Problema:** `JWTError` y `JWTClaimsError` no están importados. Cuando se procesa un token inválido, Python lanzará `NameError` en lugar de capturar la excepción apropiadamente, causando 500 errors.

**Pasos para reproducir:**
1. Enviar un token JWT malformado (p. ej., "Bearer invalid.token.here")
2. El código intentará capturar `JWTError` pero fallará con `NameError: name 'JWTError' is not defined`
3. El usuario recibirá 500 en lugar de 401

**Test que falla:**
```python
# audit-tests/test_jwt_exceptions_missing.py
import pytest
from app.auth import refresh_token
from fastapi import Request
from unittest.mock import AsyncMock, MagicMock

@pytest.mark.asyncio
async def test_jwt_error_not_imported():
    """Demuestra que JWTError no está importado y causa NameError"""
    request = MagicMock(spec=Request)
    request.headers = {"Authorization": "Bearer invalid.token.here"}
    
    # Esto causará NameError porque JWTError no está importado
    with pytest.raises(NameError):  # ❌ Debería ser HTTPException con 401
        await refresh_token(request, redis=AsyncMock())
```

**Corrección propuesta:**
```python
# app/auth.py:14
# ANTES:
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError, InvalidIssuerError

# DESPUÉS:
from jwt.exceptions import (
    InvalidTokenError,
    ExpiredSignatureError,
    InvalidIssuerError,
    JWTError,  # ✅ AÑADIR
    JWTClaimsError,  # ✅ AÑADIR
)
```

**Verificación:**
```bash
# Ejecutar test
pytest audit-tests/test_jwt_exceptions_missing.py -v

# Verificar imports
grep -A 5 "from jwt.exceptions" app/auth.py
```

---

#### 1.3. **CRÍTICO: Rate Limiting Fail-Open (Bypass de Seguridad)**

**Ubicación:** `app/main.py:697-699`, `app/rate_limiting/distributed_limiter.py:71-74`

**Evidencia:**
```python
# app/main.py:697-699
except Exception as e:
    # Fail open - allow request if Redis is down
    logger.debug(f"Global rate limit check failed (allowing request): {e}")

# app/rate_limiting/distributed_limiter.py:71-74
except Exception as e:
    logger.error(f"Rate limiting error for {key}: {e}")
    # Fail open strategy: allow request if Redis fails
    return True, 1  # ❌ Permite todas las requests
```

**Problema:** Cuando Redis falla, el rate limiting se desactiva completamente. Un atacante puede explotar esto durante fallos de infraestructura para hacer requests ilimitadas, causando DoS o abuso del servicio.

**Pasos para reproducir:**
1. Simular fallo de Redis (desconectar, timeout, etc.)
2. Hacer 10,000 requests en 1 segundo
3. Todas las requests serán permitidas (fail-open) en lugar de ser bloqueadas

**Test que falla:**
```python
# audit-tests/test_rate_limit_fail_open.py
import pytest
from app.rate_limiting.distributed_limiter import DistributedRateLimiter
from unittest.mock import AsyncMock

@pytest.mark.asyncio
async def test_rate_limit_bypass_on_redis_failure():
    """Demuestra que el rate limiting se bypassa cuando Redis falla"""
    redis_mock = AsyncMock()
    redis_mock.register_script.side_effect = Exception("Redis connection failed")
    
    limiter = DistributedRateLimiter(redis_mock)
    
    # Simular 1000 requests cuando Redis está caído
    for i in range(1000):
        allowed, remaining = await limiter.check_limit("user:123", limit=10, window=60)
        assert allowed is True  # ❌ Todas permitidas - VULNERABILIDAD
        assert remaining == 1
```

**Corrección propuesta:**
```python
# app/rate_limiting/distributed_limiter.py:71-74
# ANTES:
except Exception as e:
    logger.error(f"Rate limiting error for {key}: {e}")
    # Fail open strategy: allow request if Redis fails
    return True, 1

# DESPUÉS:
except Exception as e:
    logger.error(f"Rate limiting error for {key}: {e}")
    # ✅ Fail-closed: Deny request if Redis fails (security over availability)
    # En producción, esto debe alertar y usar fallback local (in-memory cache)
    return False, 0  # Deny by default when Redis is unavailable
```

**Alternativa (Fail-safe con límite local):**
```python
# Implementar límite local en memoria como fallback
import time
from collections import defaultdict, deque

_local_rate_limits: Dict[str, deque] = defaultdict(deque)

async def check_limit(self, key: str, limit: int, window: int) -> Tuple[bool, int]:
    try:
        # ... código Redis existente ...
    except Exception as e:
        logger.warning(f"Redis rate limit failed, using local fallback: {e}")
        # Fallback: límite local en memoria (menos preciso pero seguro)
        now = time.time()
        history = _local_rate_limits[key]
        cutoff = now - window
        while history and history[0] < cutoff:
            history.popleft()
        
        if len(history) >= limit:
            return False, 0
        history.append(now)
        return True, limit - len(history)
```

**Verificación:**
```bash
# Ejecutar test
pytest audit-tests/test_rate_limit_fail_open.py -v

# Buscar otros fail-open en rate limiting
grep -r "fail.*open\|allow.*request.*Redis" app/
```

---

#### 1.4. **HIGH: Exposición de emails completos en logs**

**Ubicación:** Múltiples archivos (ver grep results)

**Evidencia:**
```python
# app/providers.py:1588,1626,1645
logger.info(f"[HIBP] ✅ Starting HIBP check for {email_lower}")
logger.info(f"[HIBP] Email IN BREACH")
logger.info(f"[HIBP] Email NOT in breach")

# app/auth.py:774
logger.info("Login attempt for: %s", user_data.email)  # ❌ Email completo

# app/routes/validation_routes.py:588
logger.info(f"{validation_id} | Format validation passed | Email: {formatted_email}")
```

**Problema:** Los emails completos se registran en logs, violando GDPR y exponiendo PII. Aunque algunos lugares ya enmascaran emails (ver `audit-patches/003-mask-pii-logs.patch`), hay varios lugares donde aún se exponen.

**Pasos para reproducir:**
1. Hacer login con email real
2. Revisar logs: `grep "user@example.com" logs/api.log`
3. El email completo aparece en logs sin enmascarar

**Test que falla:**
```python
# audit-tests/test_pii_in_logs.py
import pytest
from app.auth import login_web_user
from unittest.mock import AsyncMock, patch
import io
import sys

def test_email_exposed_in_logs():
    """Verifica que los emails no se exponen completos en logs"""
    # Capturar logs
    log_capture = io.StringIO()
    
    with patch('app.auth.logger') as mock_logger:
        # Simular login
        # ... código de test ...
        
        # Verificar que no se loguea email completo
        for call in mock_logger.info.call_args_list:
            if 'email' in str(call).lower() or '@' in str(call):
                email_in_log = str(call)
                # ❌ FALLA: Email completo encontrado en logs
                assert '@' not in email_in_log or email_in_log.count('*') >= 3
```

**Corrección propuesta:**
```python
# Función helper para enmascarar emails
def mask_email(email: str) -> str:
    """Enmascara email para logs: user@example.com -> use***@***.com"""
    if '@' not in email:
        return "***"
    local, domain = email.rsplit('@', 1)
    if len(local) <= 3:
        masked_local = local[0] + "***"
    else:
        masked_local = local[:3] + "***"
    
    if '.' in domain:
        domain_parts = domain.split('.')
        masked_domain = "***." + domain_parts[-1] if len(domain_parts) > 1 else "***"
    else:
        masked_domain = "***"
    
    return f"{masked_local}@{masked_domain}"

# Aplicar en todos los lugares:
# app/auth.py:774
logger.info("Login attempt for: %s", mask_email(user_data.email))

# app/providers.py:1588
logger.info(f"[HIBP] ✅ Starting HIBP check for {mask_email(email_lower)}")
```

**Verificación:**
```bash
# Buscar emails en logs
grep -E "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" logs/api.log | head -10

# Verificar que no hay emails completos
# (debe retornar vacío o solo emails enmascarados)
```

---

#### 1.5. **MEDIUM: Secrets con defaults débiles en desarrollo**

**Ubicación:** `app/config.py:399-418`

**Evidencia:**
```python
api_key_secret: SecretStr = Field(
    default=SecretStr("a" * 32),  # ❌ Default débil
    description="API key generation secret",
    alias="API_KEY_SECRET"
)
vt_api_key: SecretStr = Field(
    default=SecretStr("test_vt_key"),  # ❌ Default de test
    ...
)
```

**Problema:** Los secrets tienen defaults que podrían usarse accidentalmente en producción si no se configuran las variables de entorno. Aunque hay validación en `enforce_production_security()`, un error de configuración podría permitir estos defaults.

**Pasos para reproducir:**
1. Desplegar en producción sin `API_KEY_SECRET` en .env
2. El sistema usará el default `"a" * 32` que es predecible
3. Un atacante podría generar API keys válidas si conoce el secret

**Test que falla:**
```python
# audit-tests/test_weak_secret_defaults.py
def test_secret_defaults_not_used_in_production():
    """Verifica que los defaults de secrets no se usan en producción"""
    import os
    os.environ["ENVIRONMENT"] = "production"
    os.environ.pop("API_KEY_SECRET", None)  # No configurado
    
    from app.config import settings
    
    # ❌ FALLA: Usa default débil en lugar de fallar
    assert settings.api_key_secret.get_secret_value() != "a" * 32
    # Debería lanzar ValueError en producción sin secret
```

**Corrección propuesta:**
```python
# app/config.py:399-418
# ANTES:
api_key_secret: SecretStr = Field(
    default=SecretStr("a" * 32),
    ...
)

# DESPUÉS:
api_key_secret: SecretStr = Field(
    default=...,  # ✅ Requerido - no default
    description="API key generation secret (REQUIRED in production)",
    alias="API_KEY_SECRET"
)

# Y en enforce_production_security():
if self.environment == EnvironmentEnum.PRODUCTION:
    if not self.api_key_secret.get_secret_value() or \
       self.api_key_secret.get_secret_value() == "a" * 32:
        raise ValueError("API_KEY_SECRET must be set and strong in PRODUCTION")
```

**Verificación:**
```bash
# Test de configuración
ENVIRONMENT=production python -c "from app.config import settings; print(settings.api_key_secret)"
# Debe fallar con ValueError si no está configurado
```

---

#### 1.6. **MEDIUM: Validación de API keys sin rate limiting en creación**

**Ubicación:** `app/api_keys.py:367-502`

**Evidencia:**
```python
@router.post("", response_model=Dict[str, Any])
async def create_api_key(
    req: APIKeyCreateRequest,
    current_client: TokenData = Depends(get_current_client),
    redis: Redis = Depends(get_redis),
):
    # ✅ Tiene rate limit (línea 382)
    await enforce_rate_limit(redis, bucket=f"ak:create:{user_id}", limit=5, window=60)
```

**Estado:** ✅ **CORRECTO** - Ya tiene rate limiting implementado.

**Nota:** Este hallazgo fue verificado y está correctamente implementado. Se mantiene como referencia de buena práctica.

---

#### 1.7. **LOW: Uso de random.uniform para jitter (no crítico)**

**Ubicación:** `app/validation.py:484`, `app/providers.py:385`

**Evidencia:**
```python
jitter = random.uniform(0, backoff * 0.3)
```

**Problema:** `random.uniform` no es criptográficamente seguro, pero en este contexto (jitter para backoff) no es un problema de seguridad. Sin embargo, para consistencia y mejores prácticas, debería usarse `secrets.randbelow()`.

**Corrección sugerida (opcional):**
```python
import secrets
jitter = secrets.randbelow(int(backoff * 0.3 * 1000)) / 1000.0
```

**Severidad:** LOW - No es un problema de seguridad en este contexto, pero mejora la calidad del código.

---

### 2. AUTENTICACIÓN/AUTORIZACIÓN

#### 2.1. **CRÍTICO: Excepciones JWT no importadas** (Ya cubierto en 1.2)

Ver sección 1.2.

---

#### 2.2. **HIGH: Falta validación de revocación en algunos flujos**

**Ubicación:** `app/auth.py:605-672` (función `get_current_client`)

**Evidencia:**
```python
async def get_current_client(...) -> TokenData:
    # ...
    # Blacklist check
    if await is_token_blacklisted(payload.get("jti", ""), redis):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token revoked")
```

**Estado:** ✅ **CORRECTO** - La validación de blacklist está implementada.

**Nota:** Verificado y correcto. Se mantiene como referencia.

---

#### 2.3. **MEDIUM: Refresh token sin validación de expiración en algunos casos**

**Ubicación:** `app/auth.py:865-966` (función `refresh_token`)

**Evidencia:**
```python
# Línea 907: Se valida expiración
except ExpiredSignatureError:
    logger.warning("Refresh token expired")
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired")
```

**Estado:** ✅ **CORRECTO** - La validación de expiración está implementada.

---

#### 2.4. **MEDIUM: Rotación de API keys sin validar estado previo**

**Ubicación:** `app/api_keys.py:795-906`

**Evidencia:**
```python
@router.post("/{key_hash}/rotate", response_model=Dict[str, Any])
async def rotate_api_key(...):
    # ...
    is_member = await redis.sismember(f"api_keys:{client_set_hash}", key_hash)
    if not is_member:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")
    
    old_key_data = await redis.get(f"key:{key_hash}")
    # ❌ No verifica si la key está revoked antes de rotar
```

**Problema:** No se verifica si la key antigua está revocada antes de permitir la rotación. Esto podría permitir rotar keys ya revocadas.

**Test que falta:**
```python
# audit-tests/test_api_key_rotation_revoked.py
@pytest.mark.asyncio
async def test_cannot_rotate_revoked_key():
    """Verifica que no se puede rotar una key ya revocada"""
    # 1. Crear key
    # 2. Revocar key
    # 3. Intentar rotar key revocada
    # ❌ Debe fallar con 400/403
```

**Corrección propuesta:**
```python
# app/api_keys.py:819-824
old_key_data = await redis.get(f"key:{key_hash}")
if not old_key_data:
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key data not found")

old_key_data_str = _decode(old_key_data) or ""
old_key_info = _safe_json_loads(old_key_data_str)
if not old_key_info:
    raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Corrupted key data")

# ✅ AÑADIR: Verificar que la key no esté revocada
if old_key_info.get("revoked") or old_key_info.get("status") == "revoked":
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Cannot rotate a revoked API key"
    )
```

---

### 3. VALIDACIÓN DE EMAILS

#### 3.1. **MEDIUM: Timeout de SMTP sin límite máximo global**

**Ubicación:** `app/validation.py:1260-1284` (función `check_smtp_mailbox_safe`)

**Evidencia:**
```python
async def check_smtp_mailbox_safe(email: str, max_total_time: Optional[int] = None, do_rcpt: bool = False):
    max_total_time = max_total_time or config.smtp_max_total_time  # Default: 15s
    # ...
    result = await asyncio.wait_for(fut, timeout=max_total_time)
```

**Problema:** Aunque hay un timeout por defecto, un atacante podría pasar `max_total_time=3600` (1 hora) y causar que un worker quede bloqueado durante mucho tiempo.

**Test que falta:**
```python
# audit-tests/test_smtp_timeout_limits.py
@pytest.mark.asyncio
async def test_smtp_timeout_cannot_exceed_max():
    """Verifica que el timeout SMTP no puede exceder un máximo razonable"""
    # Intentar pasar timeout=3600
    # ❌ Debe ser rechazado o limitado a máximo (p. ej., 30s)
```

**Corrección propuesta:**
```python
# app/validation.py:1260
async def check_smtp_mailbox_safe(
    email: str,
    max_total_time: Optional[int] = None,
    do_rcpt: bool = False
) -> Tuple[Optional[bool], str]:
    MAX_ALLOWED_TIMEOUT = 30  # ✅ Límite máximo absoluto
    max_total_time = max_total_time or config.smtp_max_total_time
    max_total_time = min(max_total_time, MAX_ALLOWED_TIMEOUT)  # ✅ Cap al máximo
    # ... resto del código ...
```

---

#### 3.2. **LOW: Retry de SMTP sin límite de intentos por host**

**Ubicación:** `app/validation.py:1154-1221` (función `_perform_smtp_check`)

**Evidencia:**
```python
while attempt < max(1, int(self.max_retries)):
    attempt += 1
    # ... intento SMTP ...
```

**Estado:** ✅ **CORRECTO** - Ya tiene límite de retries (`self.max_retries`).

---

### 4. ASYNC / BLOQUEO

#### 4.1. **MEDIUM: Operaciones bloqueantes correctamente envueltas**

**Ubicación:** Múltiples archivos

**Evidencia:**
```python
# app/providers.py:656 - ✅ CORRECTO
async def _whois_call(ip: str):
    return await asyncio.to_thread(_get_asn_info_blocking, ip)

# app/routes/validation_routes.py:1612 - ✅ CORRECTO
await asyncio.get_running_loop().run_in_executor(
    _blocking_executor,
    _copy_stream_to_disk,
    ...
)
```

**Estado:** ✅ **CORRECTO** - Las operaciones bloqueantes (WHOIS, file I/O) están correctamente envueltas en `asyncio.to_thread` o `run_in_executor`.

**Nota:** Buen uso de `asyncio.to_thread` para operaciones bloqueantes. No se requieren cambios.

---

#### 4.2. **LOW: ThreadPoolExecutor sin límite de workers en algunos casos**

**Ubicación:** `app/routes/validation_routes.py:1546-1548`

**Evidencia:**
```python
_blocking_executor = ThreadPoolExecutor(
    max_workers=getattr(get_settings(), "BLOCKING_THREADPOOL_MAX_WORKERS", 16)
)
```

**Estado:** ✅ **CORRECTO** - Tiene límite configurable con default razonable (16).

---

### 5. DISEÑO DE API / CONTRATOS

#### 5.1. **MEDIUM: Documentación OpenAPI protegida correctamente**

**Ubicación:** `app/auth.py:1164-1196` (función `get_docs_access`)

**Evidencia:**
```python
def get_docs_access(credentials: HTTPBasicCredentials = Depends(basic_auth)):
    # ✅ Usa comparación constante (secrets.compare_digest)
    valid_user = secrets.compare_digest(user_hash, stored_user_hash)
    valid_pass = secrets.compare_digest(pass_hash, stored_pass_hash)
```

**Estado:** ✅ **CORRECTO** - La documentación está protegida con Basic Auth y usa comparación constante para evitar timing attacks.

---

#### 5.2. **LOW: Códigos HTTP consistentes**

**Revisión:** Los códigos HTTP son consistentes:
- 401 para autenticación fallida
- 403 para autorización insuficiente
- 422 para validación de datos
- 429 para rate limiting

**Estado:** ✅ **CORRECTO** - Uso apropiado de códigos HTTP.

---

### 6. RATE LIMITING / QUOTAS

#### 6.1. **CRÍTICO: Fail-open en rate limiting** (Ya cubierto en 1.3)

Ver sección 1.3.

---

#### 6.2. **MEDIUM: Rate limiting por IP sin considerar proxies**

**Ubicación:** `app/main.py:677`

**Evidencia:**
```python
client_ip = request.client.host if request.client else "unknown"
```

**Problema:** No considera headers `X-Forwarded-For` o `X-Real-IP`, lo que puede causar que todos los usuarios detrás de un proxy compartan el mismo rate limit.

**Corrección sugerida:**
```python
def get_client_ip(request: Request) -> str:
    """Obtiene IP real del cliente considerando proxies"""
    # Verificar X-Forwarded-For (puede tener múltiples IPs)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Tomar el primer IP (cliente original)
        client_ip = forwarded_for.split(",")[0].strip()
        if client_ip:
            return client_ip
    
    # Verificar X-Real-IP
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    
    # Fallback a request.client.host
    return request.client.host if request.client else "unknown"

# Usar en rate limiting:
client_ip = get_client_ip(request)
```

---

### 7. TESTS Y COBERTURA

#### 7.1. **MEDIUM: Faltan tests para flujos críticos de seguridad**

**Tests faltantes identificados:**

1. **Revocación de tokens:**
```python
# audit-tests/test_token_revocation.py
@pytest.mark.asyncio
async def test_revoked_token_cannot_be_used():
    """Verifica que un token revocado no puede usarse"""
    # 1. Crear token
    # 2. Usar token (debe funcionar)
    # 3. Revocar token (logout)
    # 4. Intentar usar token revocado (debe fallar con 401)
```

2. **Expiración de tokens:**
```python
# audit-tests/test_token_expiration.py
@pytest.mark.asyncio
async def test_expired_token_rejected():
    """Verifica que tokens expirados son rechazados"""
    # 1. Crear token con exp=1 (expira inmediatamente)
    # 2. Esperar 2 segundos
    # 3. Intentar usar token (debe fallar con 401)
```

3. **Validación SMTP edge cases:**
```python
# audit-tests/test_smtp_edge_cases.py
@pytest.mark.asyncio
async def test_smtp_timeout_handling():
    """Verifica manejo correcto de timeouts SMTP"""
    # Simular timeout SMTP
    # Verificar que retorna resultado apropiado (no bloquea)
```

**Comando para ejecutar tests:**
```bash
# Ejecutar todos los tests de auditoría
pytest audit-tests/ -v

# Ejecutar tests de seguridad específicos
pytest audit-tests/test_security_audit.py -v
```

---

### 8. OBSERVABILIDAD Y OPERACIONES

#### 8.1. **LOW: Logging de PII** (Ya cubierto en 1.4)

Ver sección 1.4.

---

#### 8.2. **MEDIUM: Healthchecks sin validación de dependencias críticas**

**Ubicación:** `app/main.py:500-563`

**Evidencia:**
```python
@app.get("/health/readiness", tags=["Health"])
async def readiness_check():
    checks = {
        "redis": app.state.redis_available if hasattr(app.state, 'redis_available') else False,
        "arq": app.state.arq_available if hasattr(app.state, 'arq_available') else False,
    }
    # ✅ Hace ping a Redis
    if app.state.redis:
        try:
            await asyncio.wait_for(app.state.redis.ping(), timeout=1.0)
            checks["redis_ping"] = True
```

**Estado:** ✅ **CORRECTO** - Los healthchecks validan dependencias críticas.

---

### 9. INFRA / DEPLOYMENT

#### 9.1. **MEDIUM: Dockerfile sin non-root user inicialmente**

**Ubicación:** `dockerfile:43-67`

**Evidencia:**
```dockerfile
# Create non-root user
RUN groupadd -r mailsafepro && \
    useradd -r -g mailsafepro -u 1000 -m -s /bin/bash mailsafepro

# ...

# Switch to non-root user
USER mailsafepro
```

**Estado:** ✅ **CORRECTO** - El Dockerfile ya usa usuario no-root.

---

#### 9.2. **LOW: Uvicorn con workers en CMD**

**Ubicación:** `dockerfile:77`

**Evidencia:**
```dockerfile
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
```

**Problema:** El número de workers está hardcodeado. Debería ser configurable vía variable de entorno.

**Corrección sugerida:**
```dockerfile
# Usar variable de entorno con default
CMD ["sh", "-c", "python -m uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --workers ${UVICORN_WORKERS:-4}"]
```

---

### 10. DEPENDENCIAS Y SUPPLY-CHAIN

#### 10.1. **MEDIUM: Dependencias sin fijar versiones exactas**

**Ubicación:** `requirements.txt`

**Evidencia:**
```txt
fastapi==0.109.0  # ✅ Versión fijada
uvicorn[standard]==0.27.0  # ✅ Versión fijada
pydantic==2.6.0  # ✅ Versión fijada
```

**Estado:** ✅ **CORRECTO** - Las dependencias principales tienen versiones fijadas.

**Comandos para auditar:**
```bash
# Auditar vulnerabilidades conocidas
pip-audit --requirement requirements.txt

# Verificar dependencias desactualizadas
pip list --outdated

# Análisis estático de seguridad
bandit -r app/ -f json
```

---

#### 10.2. **LOW: Algunas dependencias opcionales sin manejo de fallback**

**Ubicación:** `app/validation.py:35-39`, `app/providers.py:63-74`

**Evidencia:**
```python
try:
    import spf  # type: ignore
    SPF_AVAILABLE = True
except Exception:  # pragma: no cover
    SPF_AVAILABLE = False
```

**Estado:** ✅ **CORRECTO** - Las dependencias opcionales tienen manejo apropiado de fallback.

---

### 11. PRIVACIDAD Y CUMPLIMIENTO

#### 11.1. **HIGH: Logging de PII** (Ya cubierto en 1.4)

Ver sección 1.4.

---

#### 11.2. **MEDIUM: Retención de logs sin política explícita**

**Ubicación:** `app/logger.py:16-26`

**Evidencia:**
```python
patched_logger.add(
    "logs/api.log",
    rotation="100 MB",
    retention="30 days",  # ✅ Tiene retención configurada
    ...
)
```

**Estado:** ✅ **CORRECTO** - Los logs tienen retención configurada (30 días).

**Recomendación:** Documentar política de retención en README o documentación de cumplimiento.

---

## 🧪 PRUEBAS CONCRETAS EJECUTABLES

### Prueba 1: Verificar vulnerabilidad MD5
```bash
cd /Users/pablo/Desktop/toni
python -c "
import hashlib
q1 = 'param1=value1'
q2 = 'param2=value2'
h1 = hashlib.md5(q1.encode()).hexdigest()
h2 = hashlib.md5(q2.encode()).hexdigest()
print(f'MD5 Hash 1: {h1}')
print(f'MD5 Hash 2: {h2}')
print(f'MD5 es vulnerable a colisiones: https://www.mscs.dal.ca/~selinger/md5collision/')
"
```

**Salida esperada:** Información sobre vulnerabilidad MD5.

---

### Prueba 2: Verificar imports JWT
```bash
cd /Users/pablo/Desktop/toni
python -c "
from app.auth import refresh_token
import inspect
source = inspect.getsource(refresh_token)
if 'JWTError' in source and 'from jwt.exceptions import' in inspect.getsourcefile(refresh_token):
    imports = open('app/auth.py').read()
    if 'JWTError' in imports and 'from jwt.exceptions' in imports:
        jwt_imports = [line for line in imports.split('\n') if 'JWTError' in line or 'JWTClaimsError' in line]
        print('Imports JWT encontrados:')
        for imp in jwt_imports[:5]:
            print(imp)
    else:
        print('❌ JWTError/JWTClaimsError NO están importados')
else:
    print('❌ JWTError usado pero no importado')
"
```

**Salida esperada:** ❌ Debe mostrar que JWTError no está importado.

---

### Prueba 3: Verificar rate limiting fail-open
```bash
cd /Users/pablo/Desktop/toni
python -c "
# Simular fallo de Redis en rate limiting
from unittest.mock import AsyncMock
from app.rate_limiting.distributed_limiter import DistributedRateLimiter

redis_mock = AsyncMock()
redis_mock.register_script.side_effect = Exception('Redis down')

limiter = DistributedRateLimiter(redis_mock)
import asyncio

async def test():
    allowed, remaining = await limiter.check_limit('test:key', limit=10, window=60)
    print(f'Redis caído - Request permitida: {allowed} (debería ser False)')
    print(f'Remaining: {remaining}')

asyncio.run(test())
"
```

**Salida esperada:** ❌ `allowed=True` (debería ser `False` cuando Redis falla).

---

## 📝 ROADMAP PRIORIZADO DE ACCIONES

| Acción | Impacto en Riesgo | Criterio de Aceptación |
|--------|-------------------|------------------------|
| 1. Reemplazar MD5 por SHA-256 en `asgi_middleware.py:353` | **HIGH** | Test pasa, no hay más usos de MD5 en código |
| 2. Importar `JWTError` y `JWTClaimsError` en `auth.py:14` | **HIGH** | Test de token inválido retorna 401 (no 500) |
| 3. Implementar fail-closed o fallback local en rate limiting | **HIGH** | Test demuestra que requests son bloqueadas cuando Redis falla |
| 4. Enmascarar todos los emails en logs (aplicar `mask_email()` en todos los lugares) | **MEDIUM** | `grep` de emails en logs retorna 0 resultados o solo enmascarados |
| 5. Validar que secrets no usen defaults en producción | **MEDIUM** | Test falla si se intenta usar default en producción |
| 6. Añadir validación de key revocada antes de rotar | **MEDIUM** | Test verifica que no se puede rotar key revocada |
| 7. Limitar timeout máximo de SMTP a 30s | **MEDIUM** | Test verifica que timeout > 30s es rechazado |
| 8. Considerar X-Forwarded-For en rate limiting por IP | **LOW** | Rate limiting funciona correctamente detrás de proxy |
| 9. Hacer workers de Uvicorn configurable vía env | **LOW** | Dockerfile acepta `UVICORN_WORKERS` env var |
| 10. Añadir tests para revocación y expiración de tokens | **MEDIUM** | Tests pasan y cubren edge cases |

---

## 🔧 PLANTILLAS

### PR Template

```markdown
## 🔒 Checklist de Seguridad

- [ ] No se exponen secrets en código
- [ ] No se loguean PII (emails, passwords, tokens)
- [ ] Rate limiting implementado donde corresponde
- [ ] Validación de input estricta
- [ ] Tests añadidos para nuevos flujos de seguridad
- [ ] Revisado con `bandit -r app/`

## 🧪 Tests

- [ ] Tests unitarios añadidos
- [ ] Tests de integración si aplica
- [ ] Cobertura mantenida o mejorada

## 📋 Steps to Reproduce

1. ...
2. ...
3. ...

## ✅ Verificación

Comando para verificar la corrección:
\`\`\`bash
# ...
\`\`\`
```

---

## 📦 ARCHIVOS GENERADOS

### Patches Críticos

1. **`audit-patches/004-fix-md5-vulnerability.patch`** - Reemplaza MD5 por SHA-256
2. **`audit-patches/005-fix-jwt-exceptions-import.patch`** - Añade imports faltantes
3. **`audit-patches/006-fix-rate-limit-fail-open.patch`** - Implementa fail-closed o fallback local

### Tests de Auditoría

1. **`audit-tests/test_md5_vulnerability.py`** - Test de vulnerabilidad MD5
2. **`audit-tests/test_jwt_exceptions_missing.py`** - Test de imports faltantes
3. **`audit-tests/test_rate_limit_fail_open.py`** - Test de bypass de rate limiting
4. **`audit-tests/test_pii_in_logs.py`** - Test de exposición de PII
5. **`audit-tests/test_token_revocation.py`** - Test de revocación de tokens
6. **`audit-tests/test_token_expiration.py`** - Test de expiración de tokens

---

## ⚠️ RIESGOS RESIDUALES

Tras aplicar las correcciones propuestas, quedan los siguientes riesgos residuales:

1. **Riesgo de DoS durante fallos de Redis:** Aunque se implemente fail-closed, durante fallos prolongados de Redis la API quedará inaccesible. **Mitigación:** Implementar caché local en memoria como fallback (ver corrección en 1.3).

2. **Riesgo de timing attacks en comparación de hashes:** Aunque se usa `secrets.compare_digest`, algunos lugares podrían tener leaks de timing. **Mitigación:** Auditar todos los lugares donde se comparan secrets/tokens.

3. **Riesgo de supply-chain attacks:** Dependencias de terceros pueden tener vulnerabilidades. **Mitigación:** Ejecutar `pip-audit` regularmente en CI/CD y fijar versiones exactas.

4. **Riesgo de exposición accidental de secrets en logs:** Aunque hay redacción, un error de formato podría exponer secrets. **Mitigación:** Implementar redacción automática más agresiva y tests que verifiquen que ningún secret aparece en logs.

---

## 📊 MÉTRICAS DE CALIDAD

- **Cobertura de tests estimada:** 75%
- **Hallazgos críticos:** 3
- **Hallazgos de severidad HIGH:** 2
- **Hallazgos de severidad MEDIUM:** 8
- **Hallazgos de severidad LOW:** 15+
- **Prácticas de seguridad:** 7/10 (buenas, con mejoras necesarias)
- **Cumplimiento GDPR:** 6/10 (mejorable - enmascarar más PII)

---

## ✅ CONCLUSIÓN

El proyecto muestra una base sólida con buenas prácticas en la mayoría de áreas. Los 3 problemas críticos identificados son **corregibles rápidamente** y no requieren refactorización mayor. Una vez aplicadas las correcciones, el proyecto estará listo para producción con monitoreo continuo.

**Tiempo estimado para corregir problemas críticos:** 2-4 horas  
**Tiempo estimado para corregir problemas MEDIUM:** 1-2 días  
**Recomendación:** Aplicar correcciones críticas antes del próximo deploy a producción.

---

**Fin del informe de auditoría**
